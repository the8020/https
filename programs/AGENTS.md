Parent DOX: [HTTPS](../AGENTS.md).

# Purpose

- Expose HTTPS policy and certificate management through ordinary programs.

# Ownership

- Own program manifests and argument boundaries. Shared policy and lifecycle
  stay in `../src/`.

# Local Contracts

- Configuration reads require `https.configuration.view`; writes use the owning
  API's permission. Snapshots contain public certificate material and secret
  references only.
- Certificate commands receive private keys only through execution-scoped secure
  input. Never return keys or put them in positional arguments or job history.
- Upload uses `--key-file`; one-time deployment import uses `--state-file`. Both
  use generic command secure-file inputs. Import returns only completion status
  and leaves local listener publication to the startup owner.
- Challenge lookup validates the kind and delegates to the exact shared lookup.
  Native ingress invokes it as system; it creates no independent service.
- Challenge's fourth boolean argument requests local lookup only, preventing
  loops when separate systems share a configured public challenge endpoint.
- Snapshot initialization ensures the single package maintenance schedule.
  Issue/renew and scheduled maintenance share the same fenced operation API.
  Issuance reports local application separately from successful storage.

# Work Guidance

- Keep program entrypoints small and reuse package-owned semantic fields and
  ordinary command helpers.

# Verification

- Run `deno task check` and `deno task test` from the package root.

# Child DOX Index

- [https/AGENTS.md](https/AGENTS.md): Own discoverable configuration,
  certificate uploads/details, and advanced HTTPS screens.
