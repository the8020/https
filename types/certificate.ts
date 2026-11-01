import { msg } from "/p/the8020/https/i18n/messages.ts";
import { choiceHelp, field, fieldMetadata, z } from "/p/the8020/db/fields.ts";

export const certificate = z.object({
  name: field(z.string().min(1).max(253), {
    label: msg("certificate.certificate_name"),
    description: msg("certificate.primary_dns_name_or_ip_identity_of"),
  }),
  source: field(z.enum(["provided", "acme", "local"]), {
    label: msg("certificate.source"),
    description: msg("certificate.uploaded_acme_issued_or_issued_by_the"),
  }),
  fingerprint: field(z.string().regex(/^[a-f0-9]{64}$/), {
    label: msg("certificate.fingerprint"),
    description: msg("certificate.sha_256_fingerprint_of_the_leaf_certificate"),
  }),
  domains: field(z.array(z.string()).min(1).max(100), {
    label: msg("certificate.covered_names"),
    description: msg("certificate.dns_names_and_ip_addresses_in_the"),
    storage: { type: "json" },
  }),
  validFrom: field(z.date(), {
    label: msg("certificate.valid_from"),
    description: msg("certificate.the_certificate_is_valid_from_this_time"),
  }),
  expiresAt: field(z.date(), {
    label: msg("certificate.expires"),
    description: msg(
      "certificate.the_certificate_must_be_replaced_before_this",
    ),
  }),
  lastError: field(z.string().max(2048), {
    label: msg("certificate.last_error"),
    description: msg("certificate.most_recent_certificate_operation_failure"),
  }),
});

export const certificateRecord = certificate.omit({ domains: true }).extend({
  fingerprint: certificate.shape.fingerprint.nullable(),
  validFrom: certificate.shape.validFrom.nullable(),
  expiresAt: certificate.shape.expiresAt.nullable(),
  lastError: certificate.shape.lastError.nullable(),
  coveredNames: field(z.string(), {
    label: msg("certificate.covered_names"),
    description: msg("certificate.dns_names_and_ip_addresses_covered_by"),
  }),
  status: field(z.string(), {
    label: msg("certificate.status"),
    description: msg("certificate.validity_of_the_stored_certificate_and_its"),
    valueHelp: choiceHelp(z.string(), [
      msg("administration.ready"),
      msg("admin.pending"),
      msg("admin.issuing"),
      msg("admin.renewing"),
      msg("admin.failed"),
      msg("admin.renewal_failed"),
      msg("admin.expired"),
      msg("admin.not_yet_valid"),
    ]),
  }),
  dueAt: field(z.date().nullable(), {
    label: msg("certificate.next_maintenance"),
    description: msg("certificate.scheduled_renewal_or_retry_time_for_this"),
  }),
  claimUntil: field(z.date().nullable(), {
    label: msg("certificate.operation_deadline"),
    description: msg(
      "certificate.an_unfinished_issuance_claim_can_be_recovered",
    ),
  }),
});

export const certificateFiles = z.object({
  name: field(z.string().max(253), fieldMetadata(certificate.shape.name)!),
  chain: field(z.string(), {
    label: msg("certificate.certificate_chain"),
    description: msg(
      "certificate.pem_leaf_certificate_followed_by_its_intermediate",
    ),
  }),
  key: field(z.string(), {
    label: msg("certificate.private_key"),
    description: msg("certificate.matching_pem_private_key_in_pkcs_8"),
  }),
});
