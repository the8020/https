import { AdminCommandError, kernel } from "@the8020/kernel";
import { requiredCommandArgument } from "/p/the8020/packages/commands.ts";
import { uploadCertificate } from "../../mod.ts";
import { applyChanges } from "../../src/configuration.ts";

export default async function upload(...args: string[]) {
  if (args.length > 2) {
    throw new AdminCommandError({
      code: "invalid_arguments",
      message: "Expected a hostname and PEM certificate chain",
    });
  }
  const result = await uploadCertificate(
    requiredCommandArgument(args, 0, "hostname"),
    requiredCommandArgument(args, 1, "PEM certificate chain"),
    kernel.execution.secret("key"),
  );
  return { saved: true, ...await applyChanges(), certificate: result };
}
