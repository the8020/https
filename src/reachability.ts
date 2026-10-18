import { Resolver } from "node:dns/promises";
import { request } from "node:http";
import { BlockList, isIP } from "node:net";
import { randomBytes } from "node:crypto";
import { putChallenge } from "./challenges.ts";
import { normalizeHostname } from "../types/policy.ts";

const blocked4 = new BlockList(), blocked6 = new BlockList();
for (
  const [network, prefix] of [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ] as const
) blocked4.addSubnet(network, prefix, "ipv4");
for (
  const [network, prefix] of [
    ["::", 96],
    ["::ffff:0:0", 96],
    ["64:ff9b::", 96],
    ["64:ff9b:1::", 48],
    ["100::", 64],
    ["2001::", 23],
    ["2001:db8::", 32],
    ["2002::", 16],
    ["3fff::", 20],
    ["5f00::", 16],
    ["fc00::", 7],
    ["fe80::", 10],
    ["fec0::", 10],
    ["ff00::", 8],
  ] as const
) blocked6.addSubnet(network, prefix, "ipv6");

export function publicAddress(address: string): boolean {
  const family = isIP(address);
  return family !== 0 && !address.includes("%") &&
    !(family === 4
      ? blocked4.check(address, "ipv4")
      : blocked6.check(address, "ipv6"));
}

export function localNames(ipAddress: string): string[] {
  return [
    ...new Set([
      "localhost",
      "127.0.0.1",
      "::1",
      ...(ipAddress && !publicAddress(ipAddress) ? [ipAddress] : []),
    ]),
  ];
}

export function publicName(name: string): string {
  name = normalizeHostname(name);
  if (
    !isIP(name) && (!name.includes(".") ||
      [".localhost", ".local", ".internal", ".home.arpa"].some((suffix) =>
        name.endsWith(suffix)
      ))
  ) {
    throw new TypeError(
      "Automatic certificates require a public DNS name or configured public IP",
    );
  }
  return name;
}

export async function resolvePublicAddresses(
  name: string,
  signal: AbortSignal,
): Promise<string[]> {
  if (signal.aborted) throw signal.reason;
  let addresses: string[];
  if (isIP(name)) addresses = [name];
  else {
    const resolver = new Resolver({ tries: 1, timeout: 30000 });
    const cancel = () => resolver.cancel();
    signal.addEventListener("abort", cancel, { once: true });
    try {
      const results = await Promise.allSettled([
        resolver.resolve4(name),
        resolver.resolve6(name),
      ]);
      addresses = [];
      for (const result of results) {
        if (result.status === "fulfilled") addresses.push(...result.value);
        else if (!["ENODATA", "ENOTFOUND"].includes(result.reason?.code)) {
          throw result.reason;
        }
      }
    } finally {
      signal.removeEventListener("abort", cancel);
    }
  }
  if (signal.aborted) throw signal.reason;
  if (addresses.length === 0 || !addresses.every(publicAddress)) {
    throw new Error("Hostname must resolve exclusively to public addresses");
  }
  return [...new Set(addresses)].slice(0, 16);
}

/** Connect only to the checked address; never resolve the Host header or follow a redirect. */
export function probeAddress(
  address: string,
  name: string,
  path: string,
  expected: string,
  signal: AbortSignal,
  port = 80,
): Promise<boolean> {
  return new Promise((resolve, reject) => {
    const req = request({
      hostname: address,
      port,
      path,
      method: "GET",
      signal,
      maxHeaderSize: 16384,
      agent: false,
      headers: { Host: isIP(name) === 6 ? `[${name}]` : name },
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk: string) => {
        body += chunk;
        if (body.length > expected.length) {
          response.destroy(new Error("Unexpected admission response"));
        }
      });
      response.on(
        "end",
        () => resolve(response.statusCode === 200 && body === expected),
      );
      response.on("error", reject);
    });
    req.on("error", reject);
    req.end();
  });
}

export async function verifyReachability(
  name: string,
  claimToken: string,
  timeoutSeconds: number,
) {
  name = publicName(name);
  const token = randomBytes(24).toString("base64url");
  const expected = randomBytes(32).toString("hex");
  await putChallenge(name, claimToken, "probe", token, expected);
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(new Error("Admission check timed out")),
    timeoutSeconds * 1000,
  );
  try {
    const addresses = await resolvePublicAddresses(name, controller.signal);
    for (const address of addresses) {
      try {
        if (
          await probeAddress(
            address,
            name,
            `/.well-known/the8020-https/${token}`,
            expected,
            controller.signal,
          )
        ) return;
      } catch {
        if (controller.signal.aborted) throw controller.signal.reason;
      }
    }
    throw new Error("Hostname does not reach this system on HTTP port 80");
  } finally {
    clearTimeout(timeout);
  }
}
