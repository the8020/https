import { assertEquals } from "@std/assert";
import { testDatabase } from "./test_database.ts";
import fixtures from "./certificate_fixtures.json" with { type: "json" };

const { cleanup, maintain } = await import("./maintenance.ts");
const { uploadCertificate, snapshot } = await import("./certificates.ts");
const { getConfiguration, saveConfiguration } = await import(
  "./configuration.ts"
);
const { beginOperation } = await import("./operations.ts");
const { default: Certificates } = await import("../tables/certificates.ts");
const { default: Versions } = await import("../tables/versions.ts");
const { default: Secrets } = await import(
  "/p/the8020/secrets/tables/secrets.ts"
);
const { getSecret } = await import("/p/the8020/secrets/mod.ts");

Deno.test("maintenance retains active and previous keys, removes abandoned attempts, and advances denied names", async () => {
  const fixture = await testDatabase();
  try {
    const configuration = await getConfiguration();
    for (
      const pair of [fixtures.server, fixtures.replacement, fixtures.server]
    ) {
      await uploadCertificate("example.test", pair.certificate, pair.key);
    }
    assertEquals((await Versions.selectAll().execute()).length, 3);
    assertEquals((await Secrets.selectAll().execute()).length, 3);
    const active = (await snapshot()).certificates[0]!;
    const claim = await beginOperation("abandoned.example.test");
    assertEquals(claim.status, "claimed");
    await Certificates.update({ claimUntil: new Date(0) })
      .where("name", "=", "abandoned.example.test").execute();
    await cleanup();
    assertEquals((await Versions.selectAll().execute()).length, 2);
    assertEquals((await Secrets.selectAll().execute()).length, 2);
    assertEquals(
      (await getSecret(active.keySecret)).value,
      fixtures.server.key,
    );
    assertEquals(
      await Certificates.selectAll()
        .where("name", "=", "abandoned.example.test").executeTakeFirst(),
      undefined,
    );
    const saved = await Certificates.selectAll().where(
      "name",
      "=",
      "example.test",
    ).executeTakeFirstOrThrow();
    const previous = await Versions.selectAll().where(
      "id",
      "=",
      saved.previousVersion!,
    ).executeTakeFirstOrThrow();
    assertEquals(
      (await getSecret(previous.keySecret)).value,
      fixtures.replacement.key,
    );
    await Certificates.update({
      source: "acme",
      admitted: true,
      dueAt: new Date(0),
    })
      .where("name", "=", "example.test").execute();
    await saveConfiguration({
      ...configuration,
      allowedDomains: ["other.test"],
    });
    assertEquals(await maintain(), []);
    const deferred = await Certificates.selectAll().where(
      "name",
      "=",
      "example.test",
    ).executeTakeFirstOrThrow();
    assertEquals(deferred.dueAt! > new Date(), true);
    assertEquals(deferred.activeVersion, saved.activeVersion);
    await saveConfiguration({ ...configuration, letsEncrypt: false });
    assertEquals(await maintain(), []);
  } finally {
    fixture.close();
  }
});
