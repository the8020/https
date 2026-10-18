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
  await requirePermission("https.configuration.view", "");
  let saved = await getConfiguration();
  const model = new Model(form(saved));
  while (true) {
    const event = await callScreen({
      id: "https",
      title: "HTTPS",
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
              title: "HTTPS",
              controls: ["enabled", "letsEncrypt", "email"],
            },
            {
              type: "list",
              id: "domains",
              title: "Allowed domains",
              bind: "domains",
              key: "name",
              display: ["name"],
              toolbar: [{ id: "add-domain", label: "Add domain" }],
            },
            {
              type: "field-group",
              title: "Enrollment limits",
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
          { id: "save", label: "Save", kind: "primary" },
          { id: "certificates", label: "Certificates" },
          { id: "advanced", label: "Advanced" },
          { id: "refresh", label: "Refresh" },
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
      title: value ? "Allowed domain" : "Add domain",
      schema: z.object({ name: domainInput }),
      model,
      header: {
        actions: [
          { id: "done", label: "Done", kind: "primary" },
          ...(value
            ? [{ id: "remove", label: "Remove", kind: "danger" as const }]
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
      ? "Saved and applied on this node"
      : `Saved; node application failed: ${result.error}`,
    result.applied ? "success" : "warning",
  );
}

export function showError(error: unknown) {
  sendMessage(
    error instanceof z.ZodError
      ? error.issues[0]?.message ?? "Invalid value"
      : error instanceof Error
      ? error.message
      : "HTTPS operation failed",
    "error",
  );
}
