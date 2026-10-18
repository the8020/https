import {
  BACK_EVENT,
  callScreen,
  copyText,
  Model,
  presentModal,
  presentPage,
  sendMessage,
  z,
} from "/p/the8020/uui/mod.ts";
import { kernel } from "@the8020/kernel";
import { type Policy, policy } from "../../types/policy.ts";
import {
  authorityCertificate,
  nodeApplication,
  proxyInput,
  trustedProxy,
} from "../../types/administration.ts";
import Authority from "../../tables/authority.ts";
import { showError } from "./program.ts";

const Proxy = z.object({ peer: trustedProxy });
const Advanced = policy.pick({
  directory: true,
  ipAddress: true,
  challengeFallback: true,
}).extend({
  proxies: z.array(Proxy).max(100),
});

/** Edit the caller's draft; its ordinary Save commits the whole policy once. */
export async function advanced(value: Policy): Promise<Policy | undefined> {
  const model = new Model({
    directory: value.directory,
    ipAddress: value.ipAddress,
    challengeFallback: value.challengeFallback,
    proxies: value.trustedProxies.map((peer) => ({ peer })),
  });
  while (true) {
    const event = await callScreen({
      id: "https-advanced",
      title: "Advanced HTTPS",
      model,
      schema: Advanced,
      controls: [{ id: "directory", bind: "directory", length: "long" }, {
        id: "ipAddress",
        bind: "ipAddress",
        length: "long",
      }, {
        id: "challengeFallback",
        bind: "challengeFallback",
        length: "long",
      }],
      layout: {
        schema: 1,
        id: "https-advanced",
        root: {
          type: "stack",
          children: [
            {
              type: "field-group",
              controls: ["directory", "ipAddress", "challengeFallback"],
            },
            {
              id: "proxies",
              type: "list",
              title: "Trusted certificate proxies",
              bind: "proxies",
              key: "peer",
              toolbar: [{ id: "add", label: "Add proxy" }],
            },
          ],
        },
      },
      header: {
        actions: [
          { id: "done", label: "Done", kind: "primary" },
          { id: "diagnostics", label: "Node diagnostics" },
          { id: "authority", label: "Local authority" },
        ],
      },
    });
    if (event.action === BACK_EVENT) return;
    try {
      if (event.action === "done") {
        return policy.parse({
          ...value,
          directory: model.data.directory,
          ipAddress: model.data.ipAddress,
          challengeFallback: model.data.challengeFallback,
          trustedProxies: model.data.proxies.map((row) => row.peer),
        });
      }
      if (event.action === "add" || event.action === "select") {
        const selected =
          event.action === "select" && typeof event.value === "string"
            ? event.value
            : undefined;
        const updated = await presentModal(() => editProxy(selected));
        if (updated !== undefined) {
          model.data.proxies = model.data.proxies.filter((row) =>
            row.peer !== selected && row.peer !== updated
          );
          if (updated !== "") model.data.proxies.push({ peer: updated });
        }
      }
      if (event.action === "diagnostics") await presentPage(diagnostics);
      if (event.action === "authority") await presentPage(authority);
    } catch (error) {
      showError(error);
    }
  }
}

async function editProxy(peer?: string): Promise<string | undefined> {
  const model = new Model({ peer: peer ?? "" });
  while (true) {
    const event = await callScreen({
      id: "https-proxy",
      title: peer ? "Trusted proxy" : "Add proxy",
      schema: z.object({ peer: proxyInput }),
      model,
      header: {
        actions: [
          { id: "done", label: "Done", kind: "primary" },
          ...(peer
            ? [{ id: "remove", label: "Remove", kind: "danger" as const }]
            : []),
        ],
      },
    });
    if (event.action === BACK_EVENT) return;
    if (event.action === "remove") return "";
    if (event.action === "done") {
      try {
        return trustedProxy.parse(model.data.peer);
      } catch (error) {
        showError(error);
      }
    }
  }
}

async function diagnostics() {
  const schema = z.object({ nodes: z.array(nodeApplication) });
  const model = new Model<z.infer<typeof schema>>({ nodes: [] });
  while (true) {
    try {
      const result = await kernel.nodes.list() as {
        nodes: {
          node: { id: string };
          error?: string;
          capacity?: {
            https?: {
              desired_revision: number;
              applied_revision: number;
              ready: boolean;
              error?: string;
            };
          };
        }[];
      };
      model.data.nodes = result.nodes.map(({ node, capacity, error }) => ({
        node: node.id,
        desired: capacity?.https?.desired_revision ?? null,
        applied: capacity?.https?.applied_revision ?? null,
        ready: capacity?.https?.ready ?? false,
        error: error ?? capacity?.https?.error ??
          (capacity?.https ? "" : "HTTPS status unavailable"),
      }));
    } catch (error) {
      model.data.nodes = [];
      showError(error);
    }
    const event = await callScreen({
      id: "https-diagnostics",
      title: "Node HTTPS diagnostics",
      schema,
      model,
      layout: {
        schema: 1,
        id: "https-diagnostics",
        root: { type: "list", bind: "nodes", key: "node" },
      },
      header: { actions: [{ id: "refresh", label: "Refresh" }] },
    });
    if (event.action === BACK_EVENT) return;
  }
}

async function authority() {
  const row = await Authority.select([Authority.certificate]).where(
    "id",
    "=",
    "local",
  ).executeTakeFirst();
  if (!row) {
    sendMessage("The local authority has not been created yet", "info");
    return;
  }
  const model = new Model({ certificate: row.certificate });
  while (true) {
    const event = await callScreen({
      id: "https-authority",
      title: "Local HTTPS authority",
      schema: z.object({ certificate: authorityCertificate }),
      model,
      controls: [{
        id: "certificate",
        bind: "certificate",
        control: "textarea",
        readOnly: true,
        length: "long",
        rowSpan: 8,
      }],
      header: { actions: [{ id: "copy", label: "Copy certificate" }] },
    });
    if (event.action === BACK_EVENT) return;
    if (event.action === "copy") copyText(row.certificate);
  }
}
