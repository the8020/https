import { db, transaction } from "/p/the8020/db/mod.ts";
import { jobs } from "/p/the8020/jobs/mod.ts";
import { deleteSecret } from "/p/the8020/secrets/mod.ts";
import Certificates from "../tables/certificates.ts";
import Configuration from "../tables/configuration.ts";
import Versions from "../tables/versions.ts";
import { covers } from "../types/policy.ts";
import { getConfiguration } from "./configuration.ts";
import { expireChallenges } from "./challenges.ts";
import { issueCertificate } from "./acme.ts";
import { localNames } from "./reachability.ts";

export async function ensureMaintenance() {
  return await jobs.ensure("the8020/https/maintenance", {
    name: "HTTPS certificate maintenance",
    programId: "the8020/https/maintenance",
    arguments: [],
    username: "system",
    sandboxGroup: "https-maintenance",
    node: "any",
    schedule: {
      datetimes: [],
      recurrence: {
        startDate: "2020-01-01",
        months: Array.from({ length: 12 }, (_, i) => i + 1),
        dayMode: "weekdays",
        dates: [],
        weekdays: [0, 1, 2, 3, 4, 5, 6],
        times: Array.from(
          { length: 96 },
          (_, i) =>
            `${String(Math.floor(i / 4)).padStart(2, "0")}:${
              String(i % 4 * 15).padStart(2, "0")
            }`,
        ),
      },
    },
  });
}

export async function cleanup() {
  await expireChallenges();
  await transaction({ timeoutMs: 2000 }, async (tx) => {
    await tx.updateTable(Configuration.table).set({ updatedAt: new Date() })
      .where("id", "=", "https").execute();
    const abandoned = await tx.selectFrom(Certificates.table).select([
      "name",
      "orderState",
    ]).where("claimUntil", "<=", new Date()).where("admitted", "=", false)
      .where("activeVersion", "is", null).orderBy("claimUntil").limit(100)
      .execute();
    for (const row of abandoned) {
      await tx.deleteFrom(Certificates.table).where("name", "=", row.name)
        .execute();
      if (row.orderState) await deleteSecret(row.orderState.keySecret, tx);
    }
    const unused = await tx.selectFrom(Versions.table).select([
      "id",
      "keySecret",
    ])
      .where((eb) =>
        eb.not(eb.exists(
          eb.selectFrom(Certificates.table).select("name")
            .whereRef("activeVersion", "=", Versions.id),
        ))
      )
      .where((eb) =>
        eb.not(eb.exists(
          eb.selectFrom(Certificates.table).select("name")
            .whereRef("previousVersion", "=", Versions.id),
        ))
      )
      .orderBy("createdAt").orderBy("id").limit(100).execute();
    for (const row of unused) {
      await tx.deleteFrom(Versions.table).where("id", "=", row.id).execute();
      await deleteSecret(row.keySecret, tx);
    }
  });
}

/** One ordinary Any schedule; claims also coordinate manual/cold requests. */
export async function maintain() {
  const configuration = await getConfiguration();
  await cleanup();
  if (!configuration.enabled) return [];
  const now = new Date();
  const candidates = await db.selectFrom(Certificates.table).select([
    "name",
    "dueAt",
    "source",
  ])
    .where("dueAt", "<=", now)
    .where((eb) =>
      eb.or([
        eb("source", "=", "local"),
        eb.and([eb("source", "=", "acme"), eb("admitted", "=", true)]),
      ])
    ).orderBy("dueAt").limit(64).execute();
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new Error("Maintenance time limit reached")),
    4 * 60000,
  );
  const results: { name: string; status: string; error?: string }[] = [];
  let next = 0;
  try {
    await Promise.all(Array.from({ length: 2 }, async () => {
      while (!controller.signal.aborted) {
        const row = candidates[next++];
        if (!row) break;
        if (
          row.source === "acme" && !configuration.letsEncrypt ||
          row.source === "local" &&
            !localNames(configuration.ipAddress).includes(row.name) ||
          !configuration.allowedDomains.some((pattern) =>
            covers(pattern, row.name)
          )
        ) {
          await Certificates.update({
            dueAt: new Date(now.getTime() + 15 * 60000),
          })
            .where("name", "=", row.name).where("dueAt", "=", row.dueAt)
            .execute();
          continue;
        }
        try {
          const result = await issueCertificate(
            row.name,
            true,
            controller.signal,
          );
          results.push({ name: row.name, status: result.status });
        } catch (error) {
          results.push({
            name: row.name,
            status: "failed",
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
    }));
  } finally {
    clearTimeout(timer);
  }
  return results;
}
