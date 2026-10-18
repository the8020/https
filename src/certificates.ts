import { newId } from "@the8020/kernel";
import { requirePermission } from "/p/the8020/auth/mod.ts";
import { transaction } from "/p/the8020/db/mod.ts";
import { deleteSecret, setSecret } from "/p/the8020/secrets/mod.ts";
import {
  invalidateIndexes,
  lockIndexRevision,
} from "/p/the8020/system/src/indexes.ts";
import Revisions from "/p/the8020/system/tables/revisions.ts";
import Certificates from "../tables/certificates.ts";
import Configuration from "../tables/configuration.ts";
import Versions from "../tables/versions.ts";
import { normalizePattern, policy } from "../types/policy.ts";
import { getConfiguration, packageId } from "./configuration.ts";
import { inspectServerCertificate } from "./validation.ts";
import { localNames } from "./reachability.ts";

export async function uploadCertificate(
  name: string,
  chain: string,
  key: string,
) {
  name = normalizePattern(name);
  await requirePermission("https.certificate.edit", name);
  return await publishCertificate(name, chain, key);
}

export async function publishCertificate(
  name: string,
  chain: string,
  key: string,
  claimToken?: string,
) {
  const inspected = inspectServerCertificate(name, chain, key);
  await getConfiguration();
  const id = newId("crt"), keySecret = `https-${id}`;
  await transaction({ timeoutMs: 2000 }, async (tx) => {
    await lockIndexRevision(tx);
    await tx.updateTable(Configuration.table).set({ updatedAt: new Date() })
      .where("id", "=", "https").execute();
    let existing = tx.updateTable(Certificates.table).set({
      updatedAt: new Date(),
    })
      .where("name", "=", inspected.name);
    if (claimToken !== undefined) {
      existing = existing.where("claimToken", "=", claimToken).where(
        "claimUntil",
        ">",
        new Date(),
      ).where("source", "in", ["acme", "local"]);
    }
    const previous = await existing.returningAll().executeTakeFirst();
    if (
      claimToken !== undefined &&
      (!previous || previous.source === "acme" && !previous.admitted)
    ) {
      throw new Error(
        "Certificate operation claim expired or name was not admitted",
      );
    }
    await setSecret({ name: keySecret, value: key }, tx);
    await tx.insertInto(Versions.table).values({
      ...inspected,
      id,
      keySecret,
      createdAt: new Date(),
    }).execute();
    const replacement = {
      activeVersion: id,
      previousVersion: previous?.activeVersion ?? null,
      source: claimToken === undefined ? "provided" as const : previous!.source,
      dueAt: claimToken === undefined ? null : new Date(
        inspected.validFrom.getTime() +
          (inspected.expiresAt.getTime() - inspected.validFrom.getTime()) *
            2 / 3,
      ),
      failures: 0,
      lastError: null,
      claimToken: null,
      claimKind: null,
      claimUntil: null,
      orderState: null,
      updatedAt: new Date(),
    };
    await tx.insertInto(Certificates.table).values({
      name: inspected.name,
      admitted: false,
      ...replacement,
    })
      .onConflict((conflict) =>
        conflict.column("name").doUpdateSet(replacement)
      ).execute();
    await invalidateIndexes(tx, [packageId]);
    if (previous?.orderState) {
      await deleteSecret(previous.orderState.keySecret, tx);
    }
  });
  return {
    name: inspected.name,
    fingerprint: inspected.fingerprint,
    expiresAt: inspected.expiresAt,
  };
}

/** Native publication consumes public records, then privately resolves keys through secrets. */
export async function snapshot() {
  await getConfiguration();
  return await transaction({ timeoutMs: 2000 }, async (tx) => {
    await lockIndexRevision(tx);
    const configuration = await tx.selectFrom(Configuration.table).select(
      "value",
    )
      .where("id", "=", "https").executeTakeFirstOrThrow();
    const revision = await tx.selectFrom(Revisions.table).select("revision")
      .where("domain", "=", `index:${packageId}`).executeTakeFirst();
    const certificates = await tx.selectFrom(Certificates.table)
      .innerJoin(Versions.table, Versions.id, Certificates.activeVersion)
      .select([
        Versions.id,
        Versions.name,
        Versions.chain,
        Versions.keySecret,
        Versions.domains,
        Versions.validFrom,
        Versions.expiresAt,
      ])
      .orderBy(Versions.name).limit(10001).execute();
    if (certificates.length > 10000) {
      throw new Error("HTTPS publication exceeds 10000 certificates");
    }
    const value = policy.parse(configuration.value);
    return {
      revision: revision?.revision ?? 0,
      configuration: { ...value, automaticNames: localNames(value.ipAddress) },
      certificates,
    };
  });
}
