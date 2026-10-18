import { assert, assertEquals, assertRejects, assertThrows } from "@std/assert";
import "./test_database.ts";
import {
  publicAddress,
  publicName,
  resolvePublicAddresses,
} from "./reachability.ts";

Deno.test("admission rejects private, reserved, scoped, and ambiguous destinations", async () => {
  for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) {
    assert(publicAddress(address));
  }
  for (
    const address of [
      "localhost",
      "127.0.0.1",
      "10.0.0.1",
      "169.254.169.254",
      "172.16.0.1",
      "192.168.0.1",
      "100.64.0.1",
      "192.0.2.1",
      "198.51.100.1",
      "203.0.113.1",
      "224.0.0.1",
      "255.255.255.255",
      "::",
      "::1",
      "fc00::1",
      "fe80::1",
      "fe80::1%eth0",
      "::ffff:127.0.0.1",
      "64:ff9b::7f00:1",
      "2001:db8::1",
      "ff02::1",
    ]
  ) {
    assertEquals(publicAddress(address), false, address);
  }
  for (
    const name of [
      "localhost",
      "app.local",
      "app.internal",
      "app.home.arpa",
      "127.1",
      "invalid",
      "a.*.com",
    ]
  ) assertThrows(() => publicName(name));
  await assertRejects(() =>
    resolvePublicAddresses("127.0.0.1", new AbortController().signal)
  );
  await assertRejects(() =>
    resolvePublicAddresses(
      "example.com",
      AbortSignal.abort(new Error("cancelled")),
    )
  );
});
