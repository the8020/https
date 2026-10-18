import { t, table, type TableDatabase } from "/p/the8020/db/mod.ts";
import { certificate } from "../types/certificate.ts";
import Versions from "./versions.ts";
import type { OrderState } from "../types/acme.ts";

const Certificates = table("the8020__https__certificates", {
  name: t.from(certificate.shape.name).primaryKey(),
  source: t.from(certificate.shape.source),
  activeVersion: t.text().nullable().references(() => Versions.id),
  previousVersion: t.text().nullable().references(() => Versions.id),
  admitted: t.boolean().default(false),
  dueAt: t.datetime().nullable(),
  failures: t.integer().default(0),
  lastError: t.from(certificate.shape.lastError).nullable(),
  claimToken: t.text().nullable(),
  claimKind: t.enum(["enroll", "renew"]).nullable(),
  claimUntil: t.datetime().nullable(),
  orderState: t.json<OrderState>().nullable(),
  updatedAt: t.datetime().defaultNow(),
}, {
  indexes: [
    { columns: ["dueAt"] },
    { columns: ["claimUntil"] },
    { columns: ["activeVersion"] },
    { columns: ["previousVersion"] },
    {
      columns: ["admitted"],
    },
  ],
});

declare module "/p/the8020/db/types.ts" {
  interface Database extends TableDatabase<typeof Certificates> {}
}

export default Certificates;
