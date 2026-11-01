import { msg } from "/p/the8020/https/i18n/messages.ts";
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
    label: msg("administration.trusted_proxy"),
    description: msg("administration.backend_ip_address_or_cidr_allowed_to"),
  },
);

export const proxyInput = field(
  z.string().max(64),
  fieldMetadata(trustedProxy)!,
);

export const nodeApplication = z.object({
  node: field(z.string(), {
    label: msg("administration.node"),
    description: msg(
      "administration.application_server_node_reporting_its_https_state",
    ),
  }),
  desired: field(z.number().int().nullable(), {
    label: msg("administration.desired_revision"),
    description: msg(
      "administration.shared_revision_this_node_is_attempting_to",
    ),
  }),
  applied: field(z.number().int().nullable(), {
    label: msg("administration.applied_revision"),
    description: msg("administration.revision_currently_used_by_this_node_s"),
  }),
  ready: field(z.boolean(), {
    label: msg("administration.ready"),
    description: msg(
      "administration.this_node_has_accepted_an_https_configuration",
    ),
  }),
  error: field(z.string(), {
    label: msg("administration.application_error"),
    description: msg(
      "administration.last_https_publication_failure_or_reason_this",
    ),
  }),
});

export const authorityCertificate = field(z.string(), {
  label: msg("administration.local_ca_certificate"),
  description: msg("administration.public_root_certificate_for_this_system_s"),
});
