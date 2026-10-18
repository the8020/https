import { assert } from "@std/assert";

Deno.test({
  name:
    "ACME loads and creates keys in ordinary Workers without environment access",
  permissions: { env: false },
  async fn() {
    // @deno-types="../vendor/acme.ts"
    const { default: acme } = await import("../vendor/acme.cjs");
    const key = await acme.crypto.createPrivateEcdsaKey();
    const [, csr] = await acme.crypto.createCsr({
      commonName: "example.test",
    }, key);
    assert(csr.toString().includes("CERTIFICATE REQUEST"));
    const client = new acme.Client({
      directoryUrl: "https://ca.example.test/directory",
      accountKey: key,
    });
    assert(client);
  },
});
