import { t, table, type TableDatabase } from "/p/the8020/db/mod.ts";
import { secretName } from "/p/the8020/secrets/types/secret.ts";
import { certificate } from "../types/certificate.ts";

const Versions = table("the8020__https__versions", {
  id: t.text().primaryKey(),
  name: t.from(certificate.shape.name),
  fingerprint: t.from(certificate.shape.fingerprint),
  chain: t.text(),
  keySecret: t.from(secretName),
  domains: t.from(certificate.shape.domains),
  validFrom: t.from(certificate.shape.validFrom),
  expiresAt: t.from(certificate.shape.expiresAt),
  createdAt: t.datetime().defaultNow(),
}, {
  indexes: [{ columns: ["name", "createdAt"] }, {
    columns: ["createdAt", "id"],
  }],
});

declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof Versions> {}
}

export default Versions;
