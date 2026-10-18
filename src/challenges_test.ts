import { assert, assertEquals, assertRejects } from "@std/assert";
import { testDatabase } from "./test_database.ts";

Deno.test("independent systems share a public challenge endpoint through one bounded hop", async () => {
  const fixture = await testDatabase();
  const originalFetch = globalThis.fetch;
  const { getConfiguration, saveConfiguration } = await import(
    "./configuration.ts"
  );
  const { resolveChallenge, putChallenge } = await import("./challenges.ts");
  const { beginOperation } = await import("./operations.ts");
  const token = "0123456789abcdef";
  let calls = 0;
  let body = "proof.value";
  globalThis.fetch = (input, options) => {
    calls++;
    assertEquals(
      String(input),
      `http://127.0.0.1:8080/.well-known/the8020-https/${token}?local=1`,
    );
    assertEquals(new Headers(options?.headers).get("host"), "example.test");
    assertEquals(options?.redirect, "error");
    assert(options?.signal);
    return Promise.resolve(new Response(body));
  };
  try {
    const defaults = await getConfiguration();
    assertEquals(
      await resolveChallenge("example.test", "probe", token),
      undefined,
    );
    assertEquals(calls, 0);
    await saveConfiguration({
      ...defaults,
      challengeFallback: "http://127.0.0.1:8080",
    });
    assertEquals(
      await resolveChallenge("Example.TEST", "probe", token),
      "proof.value",
    );
    assertEquals(calls, 1);
    assertEquals(
      await resolveChallenge("example.test", "probe", token, true),
      undefined,
    );
    assertEquals(
      await resolveChallenge("example.test", "probe", "../invalid"),
      undefined,
    );
    assertEquals(calls, 1);
    body = "x".repeat(2049);
    await assertRejects(() => resolveChallenge("example.test", "probe", token));
    body = "<html>not a challenge</html>";
    assertEquals(
      await resolveChallenge("example.test", "probe", token),
      undefined,
    );
    const claim = await beginOperation("example.test");
    assert(claim.status === "claimed");
    await putChallenge(
      "example.test",
      claim.token,
      "probe",
      token,
      "local.proof",
    );
    const before = calls;
    assertEquals(
      await resolveChallenge("example.test", "probe", token),
      "local.proof",
    );
    assertEquals(calls, before);
    for (
      const url of [
        "ftp://example.test",
        "http://user:password@example.test",
        "http://example.test/path",
        "http://example.test?query",
      ]
    ) {
      await assertRejects(() =>
        saveConfiguration({ ...defaults, challengeFallback: url })
      );
    }
  } finally {
    globalThis.fetch = originalFetch;
    fixture.close();
  }
});
