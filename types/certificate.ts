import { field, fieldMetadata, z } from "/p/the8020/db/fields.ts";

export const certificate = z.object({
  name: field(z.string().min(1).max(253), {
    label: "Certificate name",
    description: "Primary DNS name or IP identity of the managed certificate.",
  }),
  source: field(z.enum(["provided", "acme", "local"]), {
    label: "Source",
    description:
      "Uploaded, ACME-issued, or issued by the system's local authority.",
  }),
  fingerprint: field(z.string().regex(/^[a-f0-9]{64}$/), {
    label: "Fingerprint",
    description: "SHA-256 fingerprint of the leaf certificate's DER encoding.",
  }),
  domains: field(z.array(z.string()).min(1).max(100), {
    label: "Covered names",
    description:
      "DNS names and IP addresses in the certificate's Subject Alternative Name extension.",
    storage: { type: "json" },
  }),
  validFrom: field(z.date(), {
    label: "Valid from",
    description: "The certificate is valid from this time.",
  }),
  expiresAt: field(z.date(), {
    label: "Expires",
    description: "The certificate must be replaced before this time.",
  }),
  lastError: field(z.string().max(2048), {
    label: "Last error",
    description: "Most recent certificate operation failure.",
  }),
});

export const certificateRecord = certificate.omit({ domains: true }).extend({
  fingerprint: certificate.shape.fingerprint.nullable(),
  validFrom: certificate.shape.validFrom.nullable(),
  expiresAt: certificate.shape.expiresAt.nullable(),
  lastError: certificate.shape.lastError.nullable(),
  coveredNames: field(z.string(), {
    label: "Covered names",
    description:
      "DNS names and IP addresses covered by the active certificate.",
  }),
  status: field(
    z.enum([
      "Ready",
      "Pending",
      "Issuing",
      "Renewing",
      "Failed",
      "Renewal failed",
      "Expired",
      "Not yet valid",
    ]),
    {
      label: "Status",
      description:
        "Validity of the stored certificate and its latest operation. Node application is shown separately in diagnostics.",
    },
  ),
  dueAt: field(z.date().nullable(), {
    label: "Next maintenance",
    description: "Scheduled renewal or retry time for this certificate.",
  }),
  claimUntil: field(z.date().nullable(), {
    label: "Operation deadline",
    description:
      "An unfinished issuance claim can be recovered after this time.",
  }),
});

export const certificateFiles = z.object({
  name: field(z.string().max(253), fieldMetadata(certificate.shape.name)!),
  chain: field(z.string(), {
    label: "Certificate chain",
    description:
      "PEM leaf certificate followed by its intermediate certificates, up to 256 KiB.",
  }),
  key: field(z.string(), {
    label: "Private key",
    description:
      "Matching PEM private key in PKCS#8, RSA, or EC format, up to 64 KiB. Stored encrypted through Secrets.",
  }),
});
