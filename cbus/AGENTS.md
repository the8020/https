Parent DOX: [HTTPS](../AGENTS.md).

# Purpose

- Declare HTTPS administration commands.

# Ownership

- Own flat `commands/*.toml` declarations; ordinary programs implement them.

# Local Contracts

- Use full program IDs and explicit mutation/restart metadata. Private keys use
  the existing secure-input declarations, never ordinary arguments.
- Multiline keys and migration JSON use metadata-declared `file_option`, bounded
  by the shared administrative client; they never pass through line-based stdin.

# Work Guidance

# Verification

- Package checks type-check command programs; native declaration discovery
  validates TOML.

# Child DOX Index

No child DOX documents. This document owns the entire local scope.
