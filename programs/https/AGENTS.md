Parent DOX: [HTTPS programs](../AGENTS.md).

# Purpose

- Provide the discoverable HTTPS configuration and certificate UUI program.

# Ownership

- Own ordinary pages, modals, layout, and draft state. Shared configuration,
  permissions, certificate validation, issuance, and publication stay in `src/`.

# Local Contracts

- Put HTTPS/Let's Encrypt, allowed domains, and enrollment limits first. Domain
  and proxy lists edit the retained draft; Save commits it once.
- Advanced edits the draft's ACME directory, IP identity, and trusted proxies.
  Done accepts the advanced draft; Back cancels it. Node diagnostics reuse
  `kernel.nodes.list()` to show all configured nodes' desired/applied revisions,
  publication errors, and unavailable status. Unknown revisions remain empty.
  The local authority page exposes only its public certificate.
- Advanced also exposes the optional one-hop challenge fallback for independent
  systems sharing public port 80. It starts empty outside the Docker pair.
- Certificate lists contain bounded public metadata; details offer replacement
  and automatic certificate retry/renewal. Never load private keys for display.
- Upload file bytes through the shared UUI picker, outside Model snapshots and
  messages. Recreate pickers after each action and validate through the shared
  certificate owner. Report committed saves separately from local publication.
- Reuse semantic fields, normal field help, lists, header actions, and Back.
  File pickers suppress text-value editing through field help.

# Work Guidance

# Verification

- Run the package checks/tests and `deno task test:browser`, which runs
  `browser_fixture.ts` through UUI's presentation harness with real package SQL.
  Cancelling either upload picker retains the modal and existing draft/files;
  this behavior belongs to the shared UUI dialog handler.

# Child DOX Index

No child DOX documents. This document owns the entire local scope.
