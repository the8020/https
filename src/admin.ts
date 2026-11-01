import { text as localizedText } from "/p/the8020/i18n/mod.ts";
import { msg } from "/p/the8020/https/i18n/messages.ts";
import { requirePermission } from "/p/the8020/auth/mod.ts";
import { db } from "/p/the8020/db/mod.ts";
import Certificates from "../tables/certificates.ts";
import Versions from "../tables/versions.ts";
import { certificateRecord } from "../types/certificate.ts";

/** Bounded public metadata for administration; no PEM or secret references. */
export async function certificateRecords(name?: string) {
  await requirePermission("https.configuration.view", "");
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
        ? localizedText(msg("admin.expired"))
        : row.validFrom && row.validFrom > now
        ? localizedText(msg("admin.not_yet_valid"))
        : row.claimUntil && row.claimUntil > now
        ? row.fingerprint
          ? localizedText(msg("admin.renewing"))
          : localizedText(msg("admin.issuing"))
        : row.lastError
        ? row.fingerprint
          ? localizedText(msg("admin.renewal_failed"))
          : localizedText(msg("admin.failed"))
        : row.fingerprint
        ? localizedText(msg("administration.ready"))
        : localizedText(msg("admin.pending")),
    })
  );
}
