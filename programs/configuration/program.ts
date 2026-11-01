import { AdminCommandError } from "@the8020/kernel";
import { requirePermission } from "/p/the8020/auth/mod.ts";
import { applyConfiguration, getConfiguration } from "../../mod.ts";

export default async function configuration(...args: string[]) {
  await requirePermission("the8020.https.configuration.view", "");
  const current = await getConfiguration();
  if (args.length === 0) return current;
  if (args.length !== 1) {
    throw new AdminCommandError({
      code: "invalid_arguments",
      message: "Expected one configuration JSON object",
    });
  }
  let draft: unknown;
  try {
    draft = JSON.parse(args[0]!);
  } catch {
    throw new AdminCommandError({
      code: "invalid_arguments",
      message: "Invalid configuration JSON",
    });
  }
  if (!draft || typeof draft !== "object" || Array.isArray(draft)) {
    throw new AdminCommandError({
      code: "invalid_arguments",
      message: "Expected a configuration object",
    });
  }
  return await applyConfiguration({ ...current, ...draft });
}
