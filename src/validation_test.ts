import { assertEquals, assertThrows } from "@std/assert";
import {
  covers,
  normalizeHostname,
  normalizePattern,
  policy,
} from "../types/policy.ts";
import { inspectServerCertificate } from "./validation.ts";
// These public test keys were generated for this test suite and protect no data.
import fixtures from "./certificate_fixtures.json" with { type: "json" };

Deno.test("hostname policy normalizes names and matches exactly one wildcard label", () => {
  assertEquals(normalizeHostname("APP.Example.COM."), "app.example.com");
  assertEquals(normalizeHostname("bücher.example"), "xn--bcher-kva.example");
  assertEquals(normalizeHostname("0:0:0:0:0:0:0:1"), "::1");
  assertEquals(normalizeHostname("::ffff:c000:201"), "192.0.2.1");
  assertEquals(normalizeHostname("::FFFF:192.0.2.1"), "192.0.2.1");
  assertEquals(normalizePattern("*.Example.COM."), "*.example.com");
  assertEquals(covers("*", "example.com"), true);
  assertEquals(covers("*.example.com", "app.example.com"), true);
  for (
    const name of [
      "example.com",
      "a.b.example.com",
      "appexample.com",
      "1.2.3.4",
    ]
  ) {
    assertEquals(covers("*.example.com", name), false);
  }
  for (
    const name of [
      "",
      "a..b",
      "https://example.com",
      "foo:80",
      "a b.com",
      "-a.test",
      "a-.test",
      "*.test",
      "*.127.0.0.1",
      "127.1",
      "a.*.com",
      "example.com..",
      "[::1]",
    ]
  ) {
    assertThrows(() => normalizePattern(name));
  }
  assertEquals(policy.parse({}).allowedDomains, ["*"]);
  assertEquals(policy.parse({}).attemptsPerHour, 2);
  assertEquals(policy.parse({ attemptsPerHour: 0 }).attemptsPerHour, 0);
  assertEquals(policy.parse({ ipAddress: "FD00:0:0::1" }).ipAddress, "fd00::1");
  assertEquals(
    policy.parse({
      trustedProxies: ["::FFFF:192.0.2.1/120", "FD00:0:0::1", "127.0.0.1"],
    }).trustedProxies,
    ["192.0.2.1/24", "fd00::1", "127.0.0.1"],
  );
  for (
    const invalid of [
      { concurrentChecks: -1 },
      { attemptsPerHour: 10001 },
      { directory: "https://user:pass@acme.test" },
      { trustedProxies: ["10.0.0.0/33"] },
      { trustedProxies: ["example.com"] },
      { trustedProxies: ["fe80::1%eth0"] },
      { trustedProxies: ["::ffff:192.0.2.1/95"] },
      { ipAddress: "fe80::1%eth0" },
    ]
  ) {
    assertEquals(policy.safeParse(invalid).success, false);
  }
});

Deno.test("supplied certificates validate RSA/EC encodings, usage, SANs, dates, and key pairing", () => {
  for (const fixture of [fixtures.server, fixtures.rsa]) {
    const inspected = inspectServerCertificate(
      "example.test",
      fixture.certificate,
      fixture.key,
    );
    assertEquals(inspected.domains, [
      "example.test",
      "*.example.test",
      "127.0.0.1",
      "::1",
    ]);
    assertEquals(
      inspectServerCertificate(
        "api.example.test",
        fixture.certificate,
        fixture.pkcs8,
      ).fingerprint,
      inspected.fingerprint,
    );
    inspectServerCertificate(
      "*.example.test",
      fixture.certificate,
      fixture.key,
    );
    inspectServerCertificate("::1", fixture.certificate, fixture.key);
    assertThrows(() =>
      inspectServerCertificate(
        "deep.api.example.test",
        fixture.certificate,
        fixture.key,
      )
    );
    assertThrows(() =>
      inspectServerCertificate("other.test", fixture.certificate, fixture.key)
    );
    assertThrows(() =>
      inspectServerCertificate(
        "example.test",
        fixture.certificate,
        fixtures.replacement.key,
      )
    );
    assertThrows(() =>
      inspectServerCertificate(
        "example.test",
        fixture.certificate + "junk",
        fixture.key,
      )
    );
    assertThrows(() =>
      inspectServerCertificate(
        "example.test",
        fixture.certificate,
        fixture.key + fixture.key,
      )
    );
    assertThrows(() =>
      inspectServerCertificate(
        "example.test",
        fixture.certificate + fixtures.replacement.certificate,
        fixture.key,
      )
    );
  }
  for (
    const fixture of [
      fixtures.client,
      fixtures.expired,
      fixtures.future,
      fixtures.ca,
    ]
  ) {
    assertThrows(() =>
      inspectServerCertificate("example.test", fixture.certificate, fixture.key)
    );
  }
});
