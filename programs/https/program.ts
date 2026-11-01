import { text as localizedText } from "/p/the8020/i18n/mod.ts";
import { msg } from "/p/the8020/https/i18n/messages.ts";
import {
  BACK_EVENT,
  callScreen,
  Model,
  presentModal,
  presentPage,
  sendMessage,
  z,
} from "/p/the8020/uui/mod.ts";
import { requirePermission } from "/p/the8020/auth/mod.ts";
import {
  applyConfiguration,
  getConfiguration,
} from "../../src/configuration.ts";
import { domainPattern, type Policy, policy } from "../../types/policy.ts";
import { domainInput } from "../../types/administration.ts";

const Domain = z.object({ name: domainPattern });
const Form = policy.omit({ allowedDomains: true, trustedProxies: true }).extend(
  {
    domains: z.array(Domain).max(1000),
  },
);
const common = [
  "enabled",
  "letsEncrypt",
  "email",
  "attemptsPerHour",
  "maximumNames",
  "concurrentChecks",
  "checkTimeoutSeconds",
];
const form = (
  { allowedDomains, trustedProxies: _proxies, ...value }: Policy,
) => ({
  ...value,
  domains: allowedDomains.map((name) => ({ name })),
});

export default async function https(): Promise<void> {
  await requirePermission("the8020.https.configuration.view", "");
  let saved = await getConfiguration();
  const model = new Model(form(saved));
  while (true) {
    const event = await callScreen({
      id: "https",
      title: msg("program.https"),
      model,
      schema: Form,
      controls: common.map((key) => ({ id: key, bind: key })),
      layout: {
        schema: 1,
        id: "https",
        root: {
          type: "stack",
          children: [
            {
              type: "field-group",
              title: msg("program.https"),
              controls: ["enabled", "letsEncrypt", "email"],
            },
            {
              type: "list",
              id: "domains",
              title: msg("program.allowed_domains"),
              bind: "domains",
              key: "name",
              display: ["name"],
              toolbar: [{ id: "add-domain", label: msg("program.add_domain") }],
            },
            {
              type: "field-group",
              title: msg("program.enrollment_limits"),
              controls: [
                "attemptsPerHour",
                "maximumNames",
                "concurrentChecks",
                "checkTimeoutSeconds",
              ],
            },
          ],
        },
      },
      header: {
        actions: [
          { id: "save", label: msg("certificates.save"), kind: "primary" },
          { id: "certificates", label: msg("program.certificates") },
          { id: "advanced", label: msg("certificates.advanced") },
          { id: "refresh", label: msg("advanced.refresh") },
        ],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "add-domain" || event.action === "select") {
        const old = event.action === "select" && typeof event.value === "string"
          ? event.value
          : undefined;
        const changed = await presentModal(() => editDomain(old));
        if (changed !== undefined) {
          const names = model.data.domains.filter((row) =>
            row.name !== old && row.name !== changed
          );
          if (changed !== "") names.push({ name: changed });
          model.data.domains = names;
        }
      }
      if (event.action === "save") {
        const { domains, ...value } = model.data;
        const result = await applyConfiguration({
          ...value,
          allowedDomains: domains.map((row) => row.name),
          trustedProxies: saved.trustedProxies,
        });
        saved = result.configuration;
        model.data = form(saved);
        savedMessage(result);
      }
      if (event.action === "refresh") {
        saved = await getConfiguration();
        model.data = form(saved);
      }
      if (event.action === "certificates") {
        const { certificates } = await import("./certificates.ts");
        await presentPage(certificates);
      }
      if (event.action === "advanced") {
        const { advanced } = await import("./advanced.ts");
        const { domains, ...draft } = model.data;
        const updated = await presentPage(() =>
          advanced({
            ...draft,
            trustedProxies: saved.trustedProxies,
            allowedDomains: domains.map((row) => row.name),
          })
        );
        if (updated) {
          saved = updated;
          model.data.directory = updated.directory;
          model.data.ipAddress = updated.ipAddress;
          model.data.challengeFallback = updated.challengeFallback;
        }
      }
    } catch (error) {
      showError(error);
    }
  }
}

async function editDomain(value?: string): Promise<string | undefined> {
  const model = new Model({ name: value ?? "" });
  while (true) {
    const event = await callScreen({
      id: "https-domain",
      title: value
        ? localizedText(msg("policy.allowed_domain"))
        : localizedText(msg("program.add_domain")),
      schema: z.object({ name: domainInput }),
      model,
      header: {
        actions: [
          { id: "done", label: msg("advanced.done"), kind: "primary" },
          ...(value
            ? [{
              id: "remove",
              label: msg("advanced.remove"),
              kind: "danger" as const,
            }]
            : []),
        ],
      },
    });
    if (event.action === BACK_EVENT) return;
    if (event.action === "remove") return "";
    if (event.action === "done") {
      try {
        return domainPattern.parse(model.data.name);
      } catch (error) {
        showError(error);
      }
    }
  }
}

export function savedMessage(result: { applied: boolean; error?: string }) {
  sendMessage(
    result.applied
      ? localizedText(msg("program.saved_and_applied_on_this_node"))
      : `Saved; node application failed: ${result.error}`,
    result.applied ? "success" : "warning",
  );
}

export function showError(error: unknown) {
  sendMessage(
    error instanceof z.ZodError
      ? error.issues[0]?.message ?? localizedText(msg("program.invalid_value"))
      : error instanceof Error
      ? error.message
      : "HTTPS operation failed",
    "error",
  );
}
