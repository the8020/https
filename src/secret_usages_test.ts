import { assertEquals } from "@std/assert";
import { testDatabase } from "./test_database.ts";
import Authority from "../tables/authority.ts";
import Versions from "../tables/versions.ts";
import { issueCertificate } from "./acme.ts";
import { getConfiguration, saveConfiguration } from "./configuration.ts";
import secretUsages from "../programs/secret-usages/program.ts";

Deno.test("secret usages report the local CA and certificate keys owned by HTTPS", async () => {
  const fixture = await testDatabase();
  try {
    await saveConfiguration({
      ...await getConfiguration(),
      letsEncrypt: false,
      attemptsPerHour: 0,
      concurrentChecks: 0,
      maximumNames: 0,
    });
    assertEquals((await issueCertificate("localhost")).status, "issued");
    const authority = await Authority.selectAll().executeTakeFirstOrThrow();
    const version = await Versions.selectAll().where(
      Versions.name,
      "=",
      "localhost",
    ).executeTakeFirstOrThrow();
    const usages = await secretUsages([
      authority.keySecret,
      version.keySecret,
      "unrelated",
    ]);
    assertEquals(
      usages.map((usage) => [usage.secret, usage.title, usage.detail]),
      [
        [authority.keySecret, "HTTPS local certificate authority", undefined],
        [version.keySecret, "HTTPS certificate localhost", "Private key"],
      ],
    );
    assertEquals(
      usages.every((usage) => usage.open.program === "the8020/https/https"),
      true,
    );
    assertEquals(await secretUsages(["unrelated"]), []);
    assertEquals(await secretUsages([]), []);
  } finally {
    fixture.close();
  }
});
