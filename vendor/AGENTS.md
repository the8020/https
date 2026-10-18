Parent DOX: [HTTPS](../AGENTS.md).

# Purpose

- Pinned external certificate dependencies.

# Ownership

- Own source entrypoints, generated bundles, and complete upstream license notices.

# Local Contracts

- Regenerate with `deno task bundle`. Ordinary package source remains unbundled. Preserve upstream types through entrypoints and @deno-types; the runtime needs no npm downloads.
- `acme-client` 5.4.0 owns the ACME protocol; `@peculiar/x509` 2.2.0 owns
  certificate inspection and local CA/leaf generation. Ship complete transitive
  dependency licenses beside each generated bundle.
- ACME ships as a minified CommonJS bundle so Deno supplies native Node built-in
  requires and bundled JSDoc cannot refer to removed dependency files. Consumers
  use its default CommonJS namespace with upstream entrypoint types.
- The ACME bundle replaces ambient `process.env` with an empty object through
  esbuild's define option. Ordinary Workers deny environment access; HTTP and
  ACME options come from package configuration. Esbuild is a build tool only.

# Work Guidance

# Verification

- Run `deno task check` and `deno task test` from the package root.

# Child DOX Index

No child DOX documents. This document owns the entire local scope.
