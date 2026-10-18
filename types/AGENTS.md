Parent DOX: [HTTPS](../AGENTS.md).

# Purpose

- HTTPS policy and certificate semantic fields.

# Ownership

- Own labels, help, normalization, and validation reused by tables, programs,
  and UUI.
- `certificate.ts` also owns public administration summaries and upload filename
  fields; `administration.ts` owns trusted-proxy and node-diagnostic fields.
- Empty form drafts reuse the validated fields' metadata. Domain/proxy Done and
  certificate Save still validate through the existing policy owners.

# Local Contracts

- Domain patterns use exact names, global `*`, or one leading wildcard label.
  Normalize international names to ASCII and reject ambiguous host syntax. IP
  literals are distinct from wildcard DNS names.
- Canonicalize IPv6 and unmap IPv4-mapped addresses for names, the default IP,
  and trusted proxies. Reject scoped addresses; mapped proxy CIDRs must have at
  least 96 prefix bits and are stored as the corresponding IPv4 network.

# Work Guidance

# Verification

- Run `deno task check` and `deno task test` from the package root.

# Child DOX Index

No child DOX documents. This document owns the entire local scope.
