import { field, t, table, type TableDatabase, z } from "/p/the8020/db/mod.ts";
import { policy } from "../types/policy.ts";

const Configuration = table("the8020__https__configuration", {
  id: t.text().primaryKey(),
  value: t.from(field(policy, { storage: { type: "json" } })),
  attempts: t.from(field(z.array(z.number()), { storage: { type: "json" } })),
  legacyImport: t.text().nullable(),
  updatedAt: t.datetime().defaultNow(),
});

declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof Configuration> {}
}

export default Configuration;
