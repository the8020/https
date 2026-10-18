Parent DOX: [HTTPS](../AGENTS.md).

# Purpose

- Authoritative HTTPS configuration and certificate state.

# Ownership

- Own table declarations; physical storage and codecs belong to db.

# Local Contracts

- Keep active and previous certificate versions immutable. Store key references
  only. Index bounded maintenance selection; changes requiring node publication
  invalidate the package revision in the same transaction.

# Work Guidance

- `configuration` holds the singleton policy and rolling-hour attempt times.
  `certificates` holds active/previous references, admission, and expiring
  operation claims. `versions` holds immutable public material and secret
  references. `challenges` uses exact identity keys and indexed expiry; reads
  also verify the owning certificate's current claim.
- `accounts` stores directory identity, account URL, and immutable key
  reference. Certificate `orderState` keeps the CSR, operation-key reference,
  directory, and resumable ACME order. Active/previous references are indexed
  for bounded retention cleanup; the renewal query uses `dueAt`.
- `authority` retains the shared local CA certificate and immutable encrypted
  key reference. Its trust identity survives certificate renewals and node loss.
- Configuration's nullable `legacyImport` digest records a completed atomic
  migration; source files remain outside package authority.

# Verification

- Run `deno task check` and `deno task test` from the package root.

# Child DOX Index

No child DOX documents. This document owns the entire local scope.
