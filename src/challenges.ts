import { db, transaction } from "/p/the8020/db/mod.ts";
import Certificates from "../tables/certificates.ts";
import Challenges from "../tables/challenges.ts";
import { normalizeHostname } from "../types/policy.ts";
import { getConfiguration } from "./configuration.ts";
import { isIP } from "node:net";

function identity(name: string, kind: "acme" | "probe", token: string) {
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(token)) {
    throw new TypeError("Invalid challenge token");
  }
  return `${kind}:${normalizeHostname(name)}:${token}`;
}

export async function putChallenge(
  name: string,
  claimToken: string,
  kind: "acme" | "probe",
  token: string,
  response: string,
) {
  name = normalizeHostname(name);
  const id = identity(name, kind, token);
  if (!/^[A-Za-z0-9_.-]{1,2048}$/.test(response)) {
    throw new TypeError("Invalid challenge response");
  }
  await transaction({ timeoutMs: 2000 }, async (tx) => {
    const owner = await tx.updateTable(Certificates.table).set({
      updatedAt: new Date(),
    })
      .where("name", "=", name).where("claimToken", "=", claimToken)
      .where("claimUntil", ">", new Date()).returning("claimUntil")
      .executeTakeFirst();
    if (!owner?.claimUntil) {
      throw new Error("Certificate operation claim expired");
    }
    const { count } = await tx.selectFrom(Challenges.table)
      .select((eb) => eb.fn.countAll<number>().as("count"))
      .where("claimToken", "=", claimToken).where("id", "!=", id)
      .executeTakeFirstOrThrow();
    if (count >= 100) {
      throw new Error("Certificate operation exceeds 100 challenges");
    }
    const challenge = {
      name,
      claimToken,
      response,
      expiresAt: owner.claimUntil,
    };
    await tx.insertInto(Challenges.table).values({ id, ...challenge })
      .onConflict((conflict) => conflict.column("id").doUpdateSet(challenge))
      .execute();
  });
}

export async function getChallenge(
  name: string,
  kind: "acme" | "probe",
  token: string,
): Promise<string | undefined> {
  let id: string;
  try {
    id = identity(name, kind, token);
  } catch {
    return undefined;
  }
  const now = new Date();
  const row = await db.selectFrom(Challenges.table).innerJoin(
    Certificates.table,
    (join) =>
      join.onRef(Certificates.name, "=", Challenges.name)
        .onRef(Certificates.claimToken, "=", Challenges.claimToken),
  )
    .select(Challenges.response).where(Challenges.id, "=", id)
    .where(Challenges.expiresAt, ">", now).where(
      Certificates.claimUntil,
      ">",
      now,
    )
    .executeTakeFirst();
  return row?.response;
}

export async function removeChallenges(claimToken: string) {
  await Challenges.delete().where("claimToken", "=", claimToken).execute();
}

/** One-hop routing for independent systems sharing public port 80. */
export async function resolveChallenge(
  name: string,
  kind: "acme" | "probe",
  token: string,
  localOnly = false,
): Promise<string | undefined> {
  try {
    identity(name, kind, token);
    name = normalizeHostname(name);
  } catch {
    return undefined;
  }
  const local = await getChallenge(name, kind, token);
  if (local !== undefined || localOnly) return local;
  const { challengeFallback } = await getConfiguration();
  if (!challengeFallback) return undefined;
  const path = kind === "acme" ? "acme-challenge" : "the8020-https";
  const url = new URL(
    `/.well-known/${path}/${token}?local=1`,
    challengeFallback,
  );
  const response = await fetch(url, {
    headers: { Host: isIP(name) === 6 ? `[${name}]` : name },
    redirect: "error",
    signal: AbortSignal.timeout(2000),
  });
  if (response.status !== 200 || !response.body) {
    await response.body?.cancel();
    return undefined;
  }
  const reader = response.body.getReader();
  const bytes = new Uint8Array(2048);
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      if (size + chunk.value.length > bytes.length) {
        throw new Error("Challenge response is too large");
      }
      bytes.set(chunk.value, size);
      size += chunk.value.length;
    }
    const value = new TextDecoder("utf-8", { fatal: true }).decode(
      bytes.subarray(0, size),
    );
    return /^[A-Za-z0-9_.-]{1,2048}$/.test(value) ? value : undefined;
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
}

export async function expireChallenges() {
  await Challenges.delete().where(
    "id",
    "in",
    db.selectFrom(Challenges.table)
      .select("id").where("expiresAt", "<=", new Date()).orderBy("expiresAt")
      .limit(100),
  ).execute();
}
