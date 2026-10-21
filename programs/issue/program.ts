import { AdminCommandError } from "@the8020/kernel";
import { requirePermission } from "/p/the8020/auth/mod.ts";
import { requiredCommandArgument } from "/p/the8020/packages/commands.ts";
import { normalizeHostname } from "../../types/policy.ts";
import { issueCertificate } from "../../src/acme.ts";
import { applyChanges } from "../../src/configuration.ts";

export default async function issue(...args: string[]) {
  if (args.length > 2 || args.length === 2 && args[1] !== "renew") {
    throw new AdminCommandError({
      code: "invalid_arguments",
      message: "Expected a hostname and optional renew",
    });
  }
  const name = normalizeHostname(requiredCommandArgument(args, 0, "hostname"));
  await requirePermission("the8020.https.certificate.edit", name);
  const result = await issueCertificate(name, args[1] === "renew");
  if (result.status === "busy") return result;
  return { ...result, ...await applyChanges() };
}
