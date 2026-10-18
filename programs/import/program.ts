import { AdminCommandError, kernel } from "@the8020/kernel";
import { importLegacyState } from "../../src/import.ts";

export default async function importState(...args: string[]) {
  if (args.length) {
    throw new AdminCommandError({
      code: "invalid_arguments",
      message: "HTTPS migration accepts only secure file input",
    });
  }
  return await importLegacyState(kernel.execution.secret("state"));
}
