import { kernel } from "@the8020/kernel";
import { requirePermission } from "/p/the8020/auth/mod.ts";
import { transaction } from "/p/the8020/db/mod.ts";
import {
  invalidateIndexes,
  lockIndexRevision,
} from "/p/the8020/system/src/indexes.ts";
import Configuration from "../tables/configuration.ts";
import { type Policy, policy } from "../types/policy.ts";

export const packageId = "the8020/https";

export async function getConfiguration(): Promise<Policy> {
  const current = await Configuration.select([Configuration.value])
    .where(Configuration.id, "=", "https").executeTakeFirst();
  if (current) return policy.parse(current.value);
  await Configuration.insert({
    id: "https",
    value: policy.parse({}),
    attempts: [],
    updatedAt: new Date(),
  })
    .onConflict((conflict) => conflict.column("id").doNothing()).execute();
  const row = await Configuration.select([Configuration.value])
    .where(Configuration.id, "=", "https").executeTakeFirstOrThrow();
  return policy.parse(row.value);
}

export async function saveConfiguration(input: unknown): Promise<Policy> {
  await requirePermission("https.configuration.edit", "");
  const value = policy.parse(input);
  await transaction({ timeoutMs: 2000 }, async (tx) => {
    await lockIndexRevision(tx);
    await tx.insertInto(Configuration.table).values({
      id: "https",
      value,
      attempts: [],
      updatedAt: new Date(),
    })
      .onConflict((conflict) =>
        conflict.column("id").doUpdateSet({ value, updatedAt: new Date() })
      ).execute();
    await invalidateIndexes(tx, [packageId]);
  });
  return value;
}

export async function applyConfiguration(input: unknown) {
  const value = await saveConfiguration(input);
  return { saved: true, ...await applyChanges(), configuration: value };
}

/** Persistence already committed; failure here must never be reported as a failed save. */
export async function applyChanges() {
  try {
    await kernel.admin.execute("kernel.reindex", { packages: packageId });
    return { applied: true };
  } catch (error) {
    return {
      applied: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}
