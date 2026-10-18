import { t, table, type TableDatabase } from "/p/the8020/db/mod.ts";
import { secretName } from "/p/the8020/secrets/types/secret.ts";

const Accounts = table("the8020__https__accounts", {
  id: t.text().primaryKey(),
  directory: t.text(),
  keySecret: t.from(secretName),
  accountUrl: t.text().nullable(),
  email: t.text(),
  createdAt: t.datetime().defaultNow(),
});

declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof Accounts> {}
}

export default Accounts;
