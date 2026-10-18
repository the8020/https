import { field, fieldMetadata, z } from "/p/the8020/db/fields.ts";
import { domainPattern, policy } from "./policy.ts";

// Drafts start empty; the existing policy fields validate Done and Save.
export const domainInput = field(
  z.string().max(255),
  fieldMetadata(domainPattern)!,
);

export const trustedProxy = field(
  policy.shape.trustedProxies.unwrap().element,
  {
    label: "Trusted proxy",
    description:
      "Backend IP address or CIDR allowed to assert RFC 9440 Client-Cert. Restrict backend access to these terminators and configure them to replace incoming certificate headers.",
  },
);

export const proxyInput = field(
  z.string().max(64),
  fieldMetadata(trustedProxy)!,
);

export const nodeApplication = z.object({
  node: field(z.string(), {
    label: "Node",
    description: "Application-server node reporting its HTTPS state.",
  }),
  desired: field(z.number().int().nullable(), {
    label: "Desired revision",
    description: "Shared revision this node is attempting to apply.",
  }),
  applied: field(z.number().int().nullable(), {
    label: "Applied revision",
    description: "Revision currently used by this node's listener.",
  }),
  ready: field(z.boolean(), {
    label: "Ready",
    description: "This node has accepted an HTTPS configuration.",
  }),
  error: field(z.string(), {
    label: "Application error",
    description:
      "Last HTTPS publication failure or reason this node's status is unavailable.",
  }),
});

export const authorityCertificate = field(z.string(), {
  label: "Local CA certificate",
  description:
    "Public root certificate for this system's local HTTPS names. Import it into clients that should trust this system's local authority.",
});
