import { assert, assertEquals, assertRejects } from "@std/assert";
import { testDatabase } from "./test_database.ts";
import fixtures from "./certificate_fixtures.json" with { type: "json" };

const { default: Configuration } = await import("../tables/configuration.ts");
const { default: Certificates } = await import("../tables/certificates.ts");
const { default: Challenges } = await import("../tables/challenges.ts");
const { default: Versions } = await import("../tables/versions.ts");
const { default: configure } = await import(
  "../programs/configuration/program.ts"
);
const { default: challengeProgram } = await import(
  "../programs/challenge/program.ts"
);
const { default: Secrets } = await import(
  "/p/the8020/secrets/tables/secrets.ts"
);
const { getConfiguration, saveConfiguration, applyConfiguration } =
  await import("./configuration.ts");
const { snapshot, uploadCertificate, publishCertificate } = await import(
  "./certificates.ts"
);
const { certificateRecords } = await import("./admin.ts");
const { beginOperation, admitName, failOperation } = await import(
  "./operations.ts"
);
const { putChallenge, getChallenge, removeChallenges, expireChallenges } =
  await import("./challenges.ts");

Deno.test("HTTPS saves preserve budgets, invalidate revisions atomically, and retain coherent key versions", async () => {
  const fixture = await testDatabase();
  try {
    const defaults = await getConfiguration();
    assertEquals(defaults.enabled, true);
    assertEquals(defaults.letsEncrypt, true);
    assertEquals(defaults.maximumNames, 10);
    assertEquals(await configure(), defaults);
    await assertRejects(() => configure("{"));
    await assertRejects(() => configure("[]"));
    await assertRejects(() => configure("{}", "extra"));
    await assertRejects(() => configure('{"unknown":true}'));
    await assertRejects(() =>
      challengeProgram("example.test", "invalid", "token")
    );
    await Configuration.update({ attempts: [Date.now()] }).where(
      "id",
      "=",
      "https",
    ).execute();
    await saveConfiguration({
      ...defaults,
      allowedDomains: ["*.example.test"],
      attemptsPerHour: 1,
    });
    assertEquals((await getConfiguration()).allowedDomains, ["*.example.test"]);
    assertEquals(
      (await Configuration.selectAll().executeTakeFirstOrThrow()).attempts
        .length,
      1,
    );
    let state = await snapshot();
    assertEquals(state.revision, 1);
    await assertRejects(() =>
      saveConfiguration({ ...defaults, allowedDomains: ["a.*.test"] })
    );
    assertEquals((await snapshot()).revision, 1);
    await uploadCertificate(
      "example.test",
      fixtures.server.certificate,
      fixtures.server.key,
    );
    state = await snapshot();
    assertEquals(state.revision, 2);
    assertEquals(state.certificates.length, 1);
    const original = state.certificates[0]!;
    const listed = (await certificateRecords("example.test"))[0]!;
    assertEquals(listed.status, "Ready");
    assertEquals(listed.expiresAt, original.expiresAt);
    assertEquals(listed.coveredNames, original.domains.join(", "));
    assert(!JSON.stringify(listed).includes("BEGIN"));
    assert(!("keySecret" in listed));
    assert(!JSON.stringify(state).includes("PRIVATE KEY"));
    assert(
      (await Secrets.selectAll().executeTakeFirstOrThrow()).value.startsWith(
        "test:",
      ),
    );
    await assertRejects(() =>
      uploadCertificate(
        "example.test",
        fixtures.replacement.certificate,
        fixtures.server.key,
      )
    );
    assertEquals((await snapshot()).revision, 2);
    fixture.failSQL = 'update "the8020__system__revisions"';
    await assertRejects(() =>
      uploadCertificate(
        "example.test",
        fixtures.replacement.certificate,
        fixtures.replacement.key,
      )
    );
    fixture.failSQL = undefined;
    assertEquals((await Versions.selectAll().execute()).length, 1);
    assertEquals((await Secrets.selectAll().execute()).length, 1);
    assertEquals((await snapshot()).certificates[0]!.id, original.id);
    await uploadCertificate(
      "example.test",
      fixtures.replacement.certificate,
      fixtures.replacement.key,
    );
    const replacement = (await snapshot()).certificates[0]!;
    assert(replacement.keySecret !== original.keySecret);
    assertEquals(
      (await Certificates.selectAll().executeTakeFirstOrThrow())
        .previousVersion,
      original.id,
    );
    assertEquals((await Versions.selectAll().execute()).length, 2);
    const result = await applyConfiguration({
      ...defaults,
      allowedDomains: ["example.test"],
    });
    assertEquals(result.saved, true);
    assertEquals(result.applied, false);
    assertEquals((await getConfiguration()).allowedDomains, ["example.test"]);
    await saveConfiguration({
      ...defaults,
      attemptsPerHour: 2,
      concurrentChecks: 1,
    });
    const claim = await beginOperation("auto.example.test");
    assert(claim.status === "claimed");
    assertEquals(
      (await certificateRecords("auto.example.test"))[0]?.status,
      "Issuing",
    );
    assertEquals((await beginOperation("auto.example.test")).status, "busy");
    await assertRejects(() => beginOperation("other.example.test"));
    assertEquals(
      (await Configuration.selectAll().executeTakeFirstOrThrow()).attempts
        .length,
      2,
    );
    assertEquals(
      await failOperation("auto.example.test", claim.token, "DNS failed"),
      true,
    );
    assertEquals(
      await Certificates.selectAll().where("name", "=", "auto.example.test")
        .executeTakeFirst(),
      undefined,
    );
    await assertRejects(() => beginOperation("auto.example.test"));

    await saveConfiguration({
      ...defaults,
      attemptsPerHour: 20,
      maximumNames: 1,
      concurrentChecks: 2,
    });
    const abandoned = await beginOperation("auto.example.test");
    assert(abandoned.status === "claimed");
    const token = "shared_acme_token_123456789";
    await putChallenge(
      "auto.example.test",
      abandoned.token,
      "acme",
      token,
      "key.authorization",
    );
    assertEquals(
      await getChallenge("auto.example.test", "acme", token),
      "key.authorization",
    );
    assertEquals(
      await getChallenge("other.example.test", "acme", token),
      undefined,
    );
    assertEquals(
      await getChallenge("auto.example.test", "probe", token),
      undefined,
    );
    assertEquals(
      await getChallenge("auto.example.test", "acme", "../invalid"),
      undefined,
    );
    await assertRejects(() => beginOperation("other.example.test"));
    await Certificates.update({ claimUntil: new Date(0) }).where(
      "name",
      "=",
      "auto.example.test",
    ).execute();
    const recovered = await beginOperation("auto.example.test");
    assert(
      recovered.status === "claimed" && recovered.token !== abandoned.token,
    );
    assertEquals(
      await getChallenge("auto.example.test", "acme", token),
      undefined,
    );
    await assertRejects(() =>
      putChallenge(
        "auto.example.test",
        abandoned.token,
        "acme",
        token,
        "stale.authorization",
      )
    );
    await putChallenge(
      "auto.example.test",
      recovered.token,
      "acme",
      token,
      "new.authorization",
    );
    await removeChallenges(abandoned.token);
    assertEquals(
      await getChallenge("auto.example.test", "acme", token),
      "new.authorization",
    );
    await Challenges.update({ expiresAt: new Date(0) }).where(
      "claimToken",
      "=",
      recovered.token,
    ).execute();
    assertEquals(
      await getChallenge("auto.example.test", "acme", token),
      undefined,
    );
    await expireChallenges();
    assertEquals((await Challenges.selectAll().execute()).length, 0);
    await assertRejects(() => admitName("auto.example.test", abandoned.token));
    await admitName("auto.example.test", recovered.token);
    await assertRejects(() =>
      publishCertificate(
        "auto.example.test",
        fixtures.server.certificate,
        fixtures.server.key,
        abandoned.token,
      )
    );
    await publishCertificate(
      "auto.example.test",
      fixtures.server.certificate,
      fixtures.server.key,
      recovered.token,
    );
    assertEquals((await beginOperation("auto.example.test")).status, "ready");

    await saveConfiguration({
      ...defaults,
      attemptsPerHour: 0,
      maximumNames: 0,
      concurrentChecks: 0,
    });
    await assertRejects(() => beginOperation("other.example.test"));
    const renewal = await beginOperation("auto.example.test", true);
    assert(renewal.status === "claimed");
    assertEquals(
      (await certificateRecords("auto.example.test"))[0]?.status,
      "Renewing",
    );
    const retryAfter = new Date(Date.now() + 3600000);
    assertEquals(
      await failOperation(
        "auto.example.test",
        renewal.token,
        "CA delayed",
        retryAfter,
      ),
      true,
    );
    assertEquals(
      (await beginOperation("auto.example.test", true)).status,
      "busy",
    );
    assertEquals((await beginOperation("auto.example.test")).status, "ready");
    assertEquals(
      (await Certificates.selectAll().where("name", "=", "auto.example.test")
        .executeTakeFirstOrThrow()).dueAt,
      retryAfter,
    );
    const delayed = (await certificateRecords("auto.example.test"))[0]!;
    assertEquals(delayed.status, "Renewal failed");
    assertEquals(delayed.lastError, "CA delayed");
    assertEquals(delayed.dueAt, retryAfter);
    await Certificates.update({ dueAt: new Date(0) }).where(
      "name",
      "=",
      "auto.example.test",
    ).execute();
    const later = await beginOperation("auto.example.test", true);
    assert(later.status === "claimed");
    await uploadCertificate(
      "auto.example.test",
      fixtures.replacement.certificate,
      fixtures.replacement.key,
    );
    await assertRejects(() =>
      publishCertificate(
        "auto.example.test",
        fixtures.server.certificate,
        fixtures.server.key,
        later.token,
      )
    );
    assertEquals(
      await failOperation("auto.example.test", later.token, "late failure"),
      false,
    );
  } finally {
    fixture.close();
  }
});
