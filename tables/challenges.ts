import { t, table, type TableDatabase } from "/p/the8020/db/mod.ts";

const Challenges = table("the8020__https__challenges", {
  id: t.text().primaryKey(),
  name: t.text(),
  claimToken: t.text(),
  response: t.text(),
  expiresAt: t.datetime(),
}, { indexes: [{ columns: ["claimToken"] }, { columns: ["expiresAt"] }] });

declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof Challenges> {}
}

export default Challenges;
