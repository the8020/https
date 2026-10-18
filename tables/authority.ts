import { t, table, type TableDatabase } from "/p/the8020/db/mod.ts";
import { secretName } from "/p/the8020/secrets/types/secret.ts";
import { certificate } from "../types/certificate.ts";

const Authority = table("the8020__https__authority", {
  id: t.text().primaryKey(),
  certificate: t.text(),
  keySecret: t.from(secretName),
  expiresAt: t.from(certificate.shape.expiresAt),
});

declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof Authority> {}
}

export default Authority;
