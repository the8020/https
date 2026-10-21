Parent DOX: [8020 workspace](../AGENTS.md).

Framework source:
[agent0ai/dox/AGENTS.md](https://github.com/agent0ai/dox/blob/765ae4ac02cc884eefcd41a3d0f71941721adb89/AGENTS.md).

# DOX framework

- DOX is highly performant AGENTS.md hierarchy installed here
- Agent must follow DOX instructions across any edits

## Core Contract

- AGENTS.md files are binding work contracts for their subtrees
- Work products, source materials, instructions, records, assets, and durable
  docs must stay understandable from the nearest applicable AGENTS.md plus every
  parent AGENTS.md above it

## Read Before Editing

1. Read the root AGENTS.md
2. Identify every file or folder you expect to touch
3. Walk from the repository root to each target path
4. Read every AGENTS.md found along each route
5. If a parent AGENTS.md lists a child AGENTS.md whose scope contains the path,
   read that child and continue from there
6. Use the nearest AGENTS.md as the local contract and parent docs for repo-wide
   rules
7. If docs conflict, the closer doc controls local work details, but no child
   doc may weaken DOX

Do not rely on memory. Re-read the applicable DOX chain in the current session
before editing.

## Update After Editing

Every meaningful change requires a DOX pass before the task is done.

Update the closest owning AGENTS.md when a change affects:

- purpose, scope, ownership, or responsibilities
- durable structure, contracts, workflows, or operating rules
- required inputs, outputs, permissions, constraints, side effects, or artifacts
- user preferences about behavior, communication, process, organization, or
  quality
- AGENTS.md creation, deletion, move, rename, or index contents

Update parent docs when parent-level structure, ownership, workflow, or child
index changes. Update child docs when parent changes alter local rules. Remove
stale or contradictory text immediately. Small edits that do not change behavior
or contracts may leave docs unchanged, but the DOX pass still must happen.

## Hierarchy

- Root AGENTS.md is the DOX rail: project-wide instructions, global preferences,
  durable workflow rules, and the top-level Child DOX Index
- Child AGENTS.md files own domain-specific instructions and their own Child DOX
  Index
- Each parent explains what its direct children cover and what stays owned by
  the parent
- The closer a doc is to the work, the more specific and practical it must be

## Child Doc Shape

- Create a child AGENTS.md when a folder becomes a durable boundary with its own
  purpose, rules, responsibilities, workflow, materials, or quality standards
- Work Guidance must reflect the current standards of the project or user
  instructions; if there are no specific standards or instructions yet, leave it
  empty
- Verification must reflect an existing check; if no verification framework
  exists yet, leave it empty and update it when one exists

Default section order:

- Purpose
- Ownership
- Local Contracts
- Work Guidance
- Verification
- Child DOX Index

## Style

- Keep docs concise, current, and operational
- Document stable contracts, not diary entries
- Put broad rules in parent docs and concrete details in child docs
- Prefer direct bullets with explicit names
- Do not duplicate rules across many files unless each scope needs a local
  version
- Delete stale notes instead of explaining history
- Trim obvious statements, repeated rules, misplaced detail, and warnings for
  risks that no longer exist

## Closeout

1. Re-check changed paths against the DOX chain
2. Update nearest owning docs and any affected parents or children
3. Refresh every affected Child DOX Index
4. Remove stale or contradictory text
5. Run existing verification when relevant
6. Report any docs intentionally left unchanged and why

## User Preferences

When the user requests a durable behavior change, record it here or in the
relevant child AGENTS.md

## Child DOX Index

- [programs/AGENTS.md](programs/AGENTS.md): Ordinary configuration, certificate,
  native publication programs, and HTTPS UUI administration.
- [cbus/AGENTS.md](cbus/AGENTS.md): HTTPS administrative command declarations.
- [declarations/AGENTS.md](declarations/AGENTS.md): Advisory authorization keys.
- [types/AGENTS.md](types/AGENTS.md): HTTPS policy and certificate field
  definitions.
- [tables/AGENTS.md](tables/AGENTS.md): Shared policy, certificate versions, and
  maintenance state.
- [src/AGENTS.md](src/AGENTS.md): Configuration, validation, and certificate
  lifecycle.
- [vendor/AGENTS.md](vendor/AGENTS.md): Pinned external certificate dependencies
  and licenses.

# Purpose

- Own HTTPS policy and certificate management as the independent `the8020/https`
  package.

# Ownership

- `widgets/` declares this package's Home tiles and categories through the
  `the8020/packages/widgets.ts` format; the tile is visible with
  `the8020.https.configuration.view`.
- Own shared configuration, domain admission, server certificate records, ACME
  operations, and HTTPS administration.
- Kernel owns listeners, immutable in-memory TLS selection, and verified
  client-certificate evidence. Users owns client enrollment and account
  eligibility. Secrets owns encrypted private material; system owns revision
  bookkeeping; jobs owns scheduled execution.

# Local Contracts

- Fresh configuration enables HTTPS and Let's Encrypt with allowed domains `*`;
  initialization never overwrites saved settings.
- Exact names and single-label `*.example.com` policies are supported. Global
  `*` is permission to enroll eligible concrete names, not a wildcard
  certificate request.
- Save policy and the package index invalidation in one transaction. Nodes
  derive local TLS state from this shared authority; no node-copy protocol or
  all-node acknowledgement.
- Private keys use immutable named-secret references, committed with certificate
  records. Program summaries and snapshots contain public metadata and secret
  references only.
- New enrollment budgets are shared across nodes, reserved before network work,
  and distinct from HTTP request limits. Existing certificates and renewals
  survive zero enrollment limits.
- Preserve local HTTPS with one shared encrypted CA for localhost, loopback, and
  a configured private IP. Local issuance and renewal use the same claims and
  maintenance schedule, independently of Let's Encrypt and enrollment budgets.
- Runtime application failures preserve the previously accepted TLS snapshot.
  Database persistence and local application status are distinct outcomes.
- The discoverable HTTPS program edits one retained policy draft and exposes
  bounded public certificate summaries, binary uploads, replacement, renewal,
  and advanced configuration. Private upload bytes never enter screen Models.

# Work Guidance

- Reuse ordinary programs, jobs, Zod fields, Kysely transactions, and the
  existing revision coordinator. Do not implement a second scheduler, ACME
  protocol, or native application database reader.
- Keep warm TLS selection free of package, database, filesystem, and PEM-parsing
  work. Bound cold work and use fenced, expiring database claims outside network
  operations.
- Follow the workspace Zen principles; keep transport native and independently
  evolving policy here.

# Verification

- Run package tasks inside an 80|20 Deno workspace; its root config supplies
  platform imports. The package config owns dependencies and tasks.

- `deno task check` checks formatting, lint, and types.
- `deno task test` exercises normal source with an isolated database and public
  test certificates.
- `deno task test:acme --pebble=<binary> --root=/root/8020/test<N>` exercises
  issuance and order recovery against an isolated local Pebble CA.
- `deno task test:browser` uses the sibling UUI presentation harness and SQLite
  to verify configuration, publication failures, server certificate replacement,
  and PEM/DER user enrollment/removal through the real screens.
- Keep multi-node and ACME acceptance checks isolated and resource-limited;
  ordinary tests never request production certificates.
