#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
DENO_COMMAND="${DENO_COMMAND:-deno}"
"$DENO_COMMAND" bundle --no-config --no-lock --keep-names --output vendor/x509.js vendor/x509.ts
"$DENO_COMMAND" bundle --no-config --no-lock --keep-names --minify --format=cjs --output vendor/acme.cjs vendor/acme.ts
# Workers use explicit package configuration, with no ambient process environment.
"$DENO_COMMAND" eval --no-config --no-lock '
  import { transform, stop } from "npm:esbuild@0.25.5";
  const source = await Deno.readTextFile("vendor/acme.cjs");
  const result = await transform(source, {
    define: { "process.env": "{}" },
    format: "cjs",
    keepNames: true,
    minify: true,
  });
  await Deno.writeTextFile("vendor/acme.cjs", result.code);
  stop();
'
