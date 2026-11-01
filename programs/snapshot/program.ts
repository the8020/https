import { requirePermission } from "/p/the8020/auth/mod.ts";
import { snapshot } from "../../mod.ts";
import { ensureMaintenance } from "../../src/maintenance.ts";

export default async function load() {
  await requirePermission("the8020.https.configuration.view", "");
  await ensureMaintenance();
  return await snapshot();
}
