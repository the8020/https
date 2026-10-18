import { assert, assertEquals, assertRejects } from "@std/assert";
import { X509Certificate } from "node:crypto";
import { testDatabase } from "./test_database.ts";
import Authority from "../tables/authority.ts";
import Certificates from "../tables/certificates.ts";
import Configuration from "../tables/configuration.ts";
import Versions from "../tables/versions.ts";
import { getSecret } from "/p/the8020/secrets/mod.ts";
import { issueCertificate } from "./acme.ts";
import { getConfiguration, saveConfiguration } from "./configuration.ts";
import { snapshot } from "./certificates.ts";
import { beginOperation } from "./operations.ts";
import { obtainLocalCertificate } from "./local.ts";
import { maintain } from "./maintenance.ts";

Deno.test("local HTTPS shares one encrypted CA and renews with enrollment and ACME disabled", async () => {
  const fixture = await testDatabase();
  try {
    await saveConfiguration({
      ...await getConfiguration(),
      letsEncrypt: false,
      attemptsPerHour: 0,
      concurrentChecks: 0,
      maximumNames: 0,
      ipAddress: "192.168.1.5",
    });
    for (const name of ["localhost", "127.0.0.1", "::1", "192.168.1.5"]) {
      assertEquals((await issueCertificate(name)).status, "issued");
    }
    const root = await Authority.selectAll().executeTakeFirstOrThrow();
    assertEquals((await Authority.selectAll().execute()).length, 1);
    const authority = new X509Certificate(root.certificate);
    assert(authority.ca);
    assert(authority.verify(authority.publicKey));
    assert((await getSecret(root.keySecret)).value.includes("PRIVATE KEY"));
    const state = await snapshot();
    assertEquals(state.configuration.automaticNames, [
      "localhost",
      "127.0.0.1",
      "::1",
      "192.168.1.5",
    ]);
    assertEquals(state.certificates.length, 4);
    assert(!JSON.stringify(state).includes("PRIVATE KEY"));
    for (const record of state.certificates) {
      const leaf = new X509Certificate(record.chain);
      assert(!leaf.ca);
      assert(leaf.verify(authority.publicKey));
      assert(
        leaf.validToDate.getTime() - leaf.validFromDate.getTime() <=
          12 * 3600000 + 60000,
      );
    }
    assertEquals(
      (await Configuration.selectAll().executeTakeFirstOrThrow()).attempts,
      [],
    );
    assertEquals((await issueCertificate("localhost")).status, "ready");
    await assertRejects(() => issueCertificate("other.local"));
    await assertRejects(() => issueCertificate("192.168.1.6"));
    await assertRejects(() => issueCertificate("public.example.com"));

    const before = await Certificates.selectAll().where(
      "name",
      "=",
      "localhost",
    ).executeTakeFirstOrThrow();
    await Certificates.update({ dueAt: new Date(0) }).where(
      "name",
      "=",
      "localhost",
    ).execute();
    assertEquals(await maintain(), [{ name: "localhost", status: "issued" }]);
    const after = await Certificates.selectAll().where("name", "=", "localhost")
      .executeTakeFirstOrThrow();
    assert(after.activeVersion !== before.activeVersion);
    assertEquals(after.previousVersion, before.activeVersion);
    assertEquals(after.source, "local");
    assertEquals(
      (await Authority.selectAll().executeTakeFirstOrThrow()).certificate,
      root.certificate,
    );

    const abandoned = await beginOperation("localhost", true);
    assert(abandoned.status === "claimed");
    assertEquals((await beginOperation("localhost", true)).status, "busy");
    await Certificates.update({ claimUntil: new Date(0) }).where(
      "name",
      "=",
      "localhost",
    ).execute();
    const recovered = await beginOperation("localhost", true);
    assert(recovered.status === "claimed");
    const versions = (await Versions.selectAll().execute()).length;
    await assertRejects(() =>
      obtainLocalCertificate("localhost", abandoned.token)
    );
    assertEquals((await Versions.selectAll().execute()).length, versions);
    await obtainLocalCertificate("localhost", recovered.token);
    assertEquals((await Authority.selectAll().execute()).length, 1);
  } finally {
    fixture.close();
  }
});
