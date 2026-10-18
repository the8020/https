import { requirePermission } from "/p/the8020/auth/mod.ts";
import { maintain } from "../../src/maintenance.ts";

export default async function maintenance() {
  await requirePermission("https.certificate.edit", "");
  return await maintain();
}
