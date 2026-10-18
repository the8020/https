Parent DOX: [HTTPS](../AGENTS.md).

# Purpose

- HTTPS configuration and certificate lifecycle.

# Ownership

- Own package policy and validation; native listeners consume public snapshots
  and resolve keys through secrets.
- `admin.ts` reads at most 10000 public certificate summaries, or one exact
  certificate for details. No private material enters administration queries.

# Local Contracts

- Validate uploaded pairs before committing. Use short transactions and never
  retain a database lock across DNS or ACME requests. Admission attempts and
  claims are shared, bounded state; expired claim owners cannot publish.
- Configuration, upload, and issuance use `applyChanges` for local publication;
  a publication failure reports already-committed persistence separately.
- Configuration-row locking serializes global enrollment capacity and policy
  changes. A four-minute claim also sets indexed `dueAt` for interrupted work.
  Existing admitted names have two renewal slots independent of new-enrollment
  limits. Publication and upload take the revision lock before this row lock.
- Local issuance uses those renewal slots and one database-owned CA whose key is
  encrypted through secrets. Create it once on demand, issue 12-hour leaves, and
  schedule renewal from validity like ACME. Never silently replace an expired
  CA: clients may already trust it. Local names and the configured private IP
  remain subject to allowed-domain policy.
- Challenge responses commit before CA notification. Exact reads verify the
  certificate's current claim and deadline; cleanup removes at most 100 expired
  responses per pass. A stale owner cannot replace a new owner's challenge.
- A configured `challengeFallback` handles independent systems sharing public
  port 80 (the Docker dev/prod pair). Missing local challenges use one HTTP hop
  with the original hostname, a two-second deadline, no redirects, and a 2048
  byte response cap. `local=1` suppresses further hops. It transfers only public
  challenge responses; certificate/account state remains in each system's DB.
- ACME account keys and URLs persist by directory. Persist order keys, CSR, and
  order state before challenges; recover the saved order under a new claim. HTTP
  requests honor claim cancellation and CA retry delays become shared backoff,
  never a sleep beyond the claim lifetime.
- Reachability resolves and rejects non-public addresses before connecting to a
  pinned literal address with the original Host. The shared proof endpoint works
  on any node; redirects are rejected.
- `importLegacyState` validates bounded migration input before one transaction
  imports policy, admission budgets, CA/account keys, and certificate versions.
  Its database marker makes retries idempotent without overwriting renewals or
  existing administrator changes. Expired cached leaves remain available as
  renewal inputs; uploaded certificates still require current validity. Import
  must finish before exposing native TLS. Unsupported input fails explicitly.
- Initialize one ordinary Any schedule through `jobs.ensure`, every 15 minutes.
  Maintenance selects at most 64 indexed due names, runs two operations at a
  time with a four-minute budget, and postpones denied names without removing
  their certificates. It removes at most 100 expired attempts, unreferenced
  versions/keys, and challenges per pass; active/previous versions remain.

# Work Guidance

# Verification

- Run `deno task check` and `deno task test` from the package root.
- The ACME runtime test denies environment access while importing the shipped
  bundle and creating client keys and a CSR.
- Storage tests cover coherent certificate/key replacement, revision rollback,
  shared enrollment budgets, abandoned-claim recovery, stale-owner rejection,
  renewal with enrollment paused, and exact shared challenge lookup/expiry.
- Local tests verify one encrypted CA, leaf signatures, IPv4/IPv6/private-IP
  coverage, renewal with ACME/enrollment disabled, and stale-owner rejection.
- `deno task test:acme --pebble=<binary> --root=/root/8020/test<N>` uses a fresh
  isolated directory and a resource-limited Pebble process. It verifies real
  HTTP-01 issuance, interrupted-order recovery, account reuse, IP certificates,
  and pinned reachability without production CA requests.

# Child DOX Index

No child DOX documents. This document owns the entire local scope.
