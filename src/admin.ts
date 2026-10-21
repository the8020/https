import { requirePermission } from "/p/the8020/auth/mod.ts";
import { db } from "/p/the8020/db/mod.ts";
import Certificates from "../tables/certificates.ts";
import Versions from "../tables/versions.ts";
import { certificateRecord } from "../types/certificate.ts";

/** Bounded public metadata for administration; no PEM or secret references. */
export async function certificateRecords(name?: string) {
  await requirePermission("the8020.https.configuration.view", "");
  let query = db.selectFrom(Certificates.table)
    .leftJoin(Versions.table, Versions.id, Certificates.activeVersion)
    .select([
      Certificates.name,
      Certificates.source,
      Certificates.dueAt,
      Certificates.lastError,
      Certificates.claimUntil,
      Versions.fingerprint,
      Versions.domains,
      Versions.validFrom,
      Versions.expiresAt,
    ]);
  if (name !== undefined) query = query.where(Certificates.name, "=", name);
  const rows = await query.orderBy(Certificates.name).limit(
    name === undefined ? 10001 : 1,
  ).execute();
  if (rows.length > 10000) {
    throw new Error("HTTPS administration exceeds 10000 certificates");
  }
  const now = new Date();
  return rows.map(({ domains, ...row }) =>
    certificateRecord.parse({
      ...row,
      coveredNames: domains?.join(", ") ?? "",
      status: row.expiresAt && row.expiresAt <= now
        ? "Expired"
        : row.validFrom && row.validFrom > now
        ? "Not yet valid"
        : row.claimUntil && row.claimUntil > now
        ? row.fingerprint ? "Renewing" : "Issuing"
        : row.lastError
        ? row.fingerprint ? "Renewal failed" : "Failed"
        : row.fingerprint
        ? "Ready"
        : "Pending",
    })
  );
}
