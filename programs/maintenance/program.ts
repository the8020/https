import { requirePermission } from "/p/the8020/auth/mod.ts";
import { maintain } from "../../src/maintenance.ts";

export default async function maintenance() {
  await requirePermission("the8020.https.certificate.edit", "");
  return await maintain();
}
