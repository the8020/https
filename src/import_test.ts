import { assert, assertEquals, assertRejects } from "@std/assert";
import { X509Certificate } from "node:crypto";
import { testDatabase } from "./test_database.ts";
import { getSecret } from "/p/the8020/secrets/mod.ts";
import Secrets from "/p/the8020/secrets/tables/secrets.ts";
import Accounts from "../tables/accounts.ts";
import Authority from "../tables/authority.ts";
import Certificates from "../tables/certificates.ts";
import Configuration from "../tables/configuration.ts";
import Versions from "../tables/versions.ts";
import { policy } from "../types/policy.ts";
import { issueCertificate } from "./acme.ts";
import { snapshot } from "./certificates.ts";
import { importLegacyState } from "./import.ts";
import fixtures from "./certificate_fixtures.json" with { type: "json" };

Deno.test("HTTPS import is atomic, retains CA/account keys and budgets, and never reimports over renewal", async () => {
  const original = await testDatabase();
  let authority, local;
  try {
    await issueCertificate("localhost");
    const ca = await Authority.selectAll().executeTakeFirstOrThrow();
    const leaf = (await snapshot()).certificates[0]!;
    authority = {
      certificate: ca.certificate,
      key: (await getSecret(ca.keySecret)).value,
    };
    local = {
      name: "localhost",
      source: "local",
      chain: leaf.chain,
      key: (await getSecret(leaf.keySecret)).value,
    };
  } finally {
    original.close();
  }
  const data = {
    configuration: policy.parse({
      attemptsPerHour: 1,
      maximumNames: 3,
      letsEncrypt: false,
    }),
    authority,
    accounts: [{
      directory: policy.parse({}).directory,
      accountUrl: "https://acme.example.test/acct/42",
      key: fixtures.server.key,
      email: "admin@example.test",
    }],
    certificates: [local, {
      name: "example.test",
      source: "provided",
      chain: fixtures.server.certificate,
      key: fixtures.server.key,
    }],
    admitted: ["pending.example.test"],
    attempts: [Date.now()],
  };
  const raw = JSON.stringify(data), fixture = await testDatabase();
  try {
    await assertRejects(
      () => importLegacyState('{"key":"PRIVATE TEST DATA'),
      TypeError,
      "Invalid HTTPS migration JSON",
    );
    await assertRejects(() =>
      importLegacyState(
        JSON.stringify({
          ...data,
          authority: { ...authority, key: fixtures.server.key },
        }),
      )
    );
    assertEquals((await Versions.selectAll().execute()).length, 0);
    fixture.failSQL = 'update "the8020__system__revisions"';
    await assertRejects(() => importLegacyState(raw));
    fixture.failSQL = undefined;
    assertEquals((await Secrets.selectAll().execute()).length, 0);
    assertEquals((await Authority.selectAll().execute()).length, 0);
    assertEquals(
      (await Configuration.selectAll().executeTakeFirstOrThrow()).legacyImport,
      null,
    );
    assertEquals(await importLegacyState(raw), { imported: true });
    const imported = await Configuration.selectAll().executeTakeFirstOrThrow();
    assertEquals(imported.value, data.configuration);
    assertEquals(imported.attempts, data.attempts);
    assert(imported.legacyImport);
    const account = await Accounts.selectAll().executeTakeFirstOrThrow();
    assertEquals(account.accountUrl, data.accounts[0]!.accountUrl);
    assertEquals(
      (await getSecret(account.keySecret)).value,
      fixtures.server.key,
    );
    const ca = await Authority.selectAll().executeTakeFirstOrThrow();
    assertEquals((await getSecret(ca.keySecret)).value, authority.key);
    const pending = await Certificates.selectAll().where(
      "name",
      "=",
      "pending.example.test",
    ).executeTakeFirstOrThrow();
    assertEquals(pending.admitted, true);
    assertEquals(pending.activeVersion, null);
    const stored = await snapshot();
    assertEquals(stored.certificates.length, 2);
    assert(!JSON.stringify(stored).includes("PRIVATE KEY"));
    const previous = stored.certificates.find((record) =>
      record.name === "localhost"
    )!.id;
    await issueCertificate("localhost", true);
    const renewed = (await snapshot()).certificates.find((record) =>
      record.name === "localhost"
    )!;
    assert(renewed.id !== previous);
    assert(
      new X509Certificate(renewed.chain).verify(
        new X509Certificate(authority.certificate).publicKey,
      ),
    );
    assertEquals(await importLegacyState(raw), { imported: false });
    assertEquals(
      (await snapshot()).certificates.find((record) =>
        record.name === "localhost"
      )!.id,
      renewed.id,
    );
    await assertRejects(
      () => importLegacyState(raw + "\n"),
      Error,
      "already completed",
    );
  } finally {
    fixture.close();
  }
});
