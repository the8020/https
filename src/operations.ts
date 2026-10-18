import { newId } from "@the8020/kernel";
import { isIP } from "node:net";
import { transaction } from "/p/the8020/db/mod.ts";
import Certificates from "../tables/certificates.ts";
import Configuration from "../tables/configuration.ts";
import Versions from "../tables/versions.ts";
import { covers, normalizeHostname, policy } from "../types/policy.ts";
import { getConfiguration } from "./configuration.ts";
import { localNames, publicName } from "./reachability.ts";

export const operationLifetimeMs = 4 * 60 * 1000;

/** Reserve shared capacity before DNS, reachability checks, or ACME work. */
export async function beginOperation(name: string, renew = false) {
  name = normalizeHostname(name);
  await getConfiguration();
  return await transaction({ timeoutMs: 2000 }, async (tx) => {
    const now = new Date();
    const locked = await tx.updateTable(Configuration.table).set({
      updatedAt: now,
    })
      .where("id", "=", "https").returningAll().executeTakeFirstOrThrow();
    const configuration = policy.parse(locked.value);
    const source = localNames(configuration.ipAddress).includes(name)
      ? "local" as const
      : "acme" as const;
    if (source === "acme") publicName(name);
    if (
      !configuration.enabled ||
      source === "acme" && (!configuration.letsEncrypt ||
          isIP(name) !== 0 && configuration.ipAddress !== name) ||
      !configuration.allowedDomains.some((pattern) => covers(pattern, name))
    ) {
      throw new Error("Automatic HTTPS is not permitted for this name");
    }
    const current = await tx.selectFrom(Certificates.table).selectAll()
      .where("name", "=", name).executeTakeFirst();
    if (current?.activeVersion && !renew) {
      const active = await tx.selectFrom(Versions.table).select([
        "id",
        "expiresAt",
      ])
        .where("id", "=", current.activeVersion).executeTakeFirstOrThrow();
      if (active.expiresAt > now) {
        return { status: "ready" as const, version: active.id };
      }
    }
    if (current && current.source !== source) {
      throw new Error("Certificate is not managed by the selected issuer");
    }
    if (current?.claimUntil && current.claimUntil > now) {
      return { status: "busy" as const, retryAt: current.claimUntil };
    }
    if (current?.failures && current.dueAt && current.dueAt > now) {
      return { status: "busy" as const, retryAt: current.dueAt };
    }
    const kind = source === "local" || current?.admitted
      ? "renew" as const
      : "enroll" as const;
    const { count: running } = await tx.selectFrom(Certificates.table)
      .select((eb) => eb.fn.countAll<number>().as("count"))
      .where("claimKind", "=", kind).where("claimUntil", ">", now)
      .executeTakeFirstOrThrow();
    if (running >= (kind === "enroll" ? configuration.concurrentChecks : 2)) {
      throw new Error("Certificate operation capacity reached");
    }
    if (kind === "enroll") {
      const attempts = locked.attempts.filter((time) =>
        time > now.getTime() - 3600000
      );
      if (attempts.length >= configuration.attemptsPerHour) {
        throw new Error("New hostname attempt allowance exhausted");
      }
      const { count: names } = await tx.selectFrom(Certificates.table)
        .select((eb) => eb.fn.countAll<number>().as("count"))
        .where("source", "!=", "local")
        .where((eb) =>
          eb.or([
            eb("admitted", "=", true),
            eb.and([eb("admitted", "=", false), eb("claimUntil", ">", now)]),
          ])
        ).executeTakeFirstOrThrow();
      if (names >= configuration.maximumNames) {
        throw new Error("Admitted hostname limit reached");
      }
      await tx.updateTable(Configuration.table).set({
        attempts: [...attempts, now.getTime()],
      })
        .where("id", "=", "https").execute();
    }
    const token = newId("tls");
    const claim = {
      claimToken: token,
      claimKind: kind,
      claimUntil: new Date(now.getTime() + operationLifetimeMs),
      dueAt: new Date(now.getTime() + operationLifetimeMs),
      updatedAt: now,
    };
    await tx.insertInto(Certificates.table).values({
      name,
      source,
      admitted: false,
      activeVersion: null,
      previousVersion: null,
      failures: 0,
      lastError: null,
      ...claim,
    })
      .onConflict((conflict) => conflict.column("name").doUpdateSet(claim))
      .execute();
    return {
      status: "claimed" as const,
      token,
      deadline: claim.claimUntil,
      configuration,
      source,
      admitted: current?.admitted ?? false,
    };
  });
}

/** A successful shared reachability proof reserves the name even if ACME later fails. */
export async function admitName(name: string, token: string) {
  await transaction({ timeoutMs: 2000 }, async (tx) => {
    const now = new Date();
    const settings = await tx.updateTable(Configuration.table).set({
      updatedAt: now,
    })
      .where("id", "=", "https").returning("value").executeTakeFirstOrThrow();
    const configuration = policy.parse(settings.value);
    if (
      !configuration.enabled || !configuration.letsEncrypt ||
      !configuration.allowedDomains.some((pattern) => covers(pattern, name))
    ) {
      throw new Error("Automatic HTTPS is no longer permitted for this name");
    }
    const current = await tx.selectFrom(Certificates.table).select("admitted")
      .where("name", "=", name).where("claimToken", "=", token)
      .where("claimUntil", ">", now).executeTakeFirst();
    if (!current) throw new Error("Certificate operation claim expired");
    if (!current.admitted) {
      const { count } = await tx.selectFrom(Certificates.table)
        .select((eb) => eb.fn.countAll<number>().as("count"))
        .where("admitted", "=", true).executeTakeFirstOrThrow();
      if (count >= configuration.maximumNames) {
        throw new Error("Admitted hostname limit reached");
      }
    }
    const changed = await tx.updateTable(Certificates.table).set({
      admitted: true,
      updatedAt: now,
    })
      .where("name", "=", name).where("claimToken", "=", token)
      .where("claimUntil", ">", new Date()).executeTakeFirst();
    if (changed.numUpdatedRows !== 1n) {
      throw new Error("Certificate operation claim expired");
    }
  });
}

export async function failOperation(
  name: string,
  token: string,
  message: string,
  retryAfter?: Date,
) {
  return await transaction({ timeoutMs: 2000 }, async (tx) => {
    const now = new Date();
    const current = await tx.updateTable(Certificates.table).set({
      updatedAt: now,
    })
      .where("name", "=", name).where("claimToken", "=", token)
      .where("claimUntil", ">", now).returningAll().executeTakeFirst();
    if (!current) return false;
    if (!current.admitted && current.source === "acme") {
      await tx.deleteFrom(Certificates.table).where("name", "=", name)
        .execute();
      return true;
    }
    const failures = Math.min(current.failures + 1, 20);
    const delay = Math.min(6 * 3600000, 30000 * 2 ** (failures - 1));
    await tx.updateTable(Certificates.table).set({
      failures,
      dueAt: new Date(
        Math.max(now.getTime() + delay, retryAfter?.getTime() ?? 0),
      ),
      lastError: message.slice(0, 2048),
      claimToken: null,
      claimKind: null,
      claimUntil: null,
    })
      .where("name", "=", name).execute();
    return true;
  });
}
