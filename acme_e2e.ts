import { assert, assertEquals, assertRejects } from "@std/assert";
import { Agent } from "node:https";
import { testDatabase } from "./src/test_database.ts";
import fixtures from "./src/certificate_fixtures.json" with { type: "json" };
import { getConfiguration, saveConfiguration } from "./src/configuration.ts";
import { admitName, beginOperation } from "./src/operations.ts";
import { getChallenge } from "./src/challenges.ts";
import { obtainCertificate } from "./src/acme.ts";
import { snapshot } from "./src/certificates.ts";
import { probeAddress } from "./src/reachability.ts";
import Certificates from "./tables/certificates.ts";
import Accounts from "./tables/accounts.ts";
// @deno-types="./vendor/acme.ts"
import acme from "./vendor/acme.cjs";

const { axios } = acme;

const option = (name: string) =>
  Deno.args.find((arg) => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
const pebble = option("pebble"), root = option("root");
if (!pebble || !root || !/^\/root\/8020\/test\d+$/.test(root)) {
  throw new Error(
    "Use --pebble=/path/to/pebble --root=/root/8020/test<N> with a fresh directory",
  );
}
await Deno.mkdir(root);
const fixture = await testDatabase();
const privateFile = `${root}/server.key`,
  certificateFile = `${root}/server.crt`;
await Deno.writeTextFile(privateFile, fixtures.server.key, { mode: 0o600 });
await Deno.writeTextFile(certificateFile, fixtures.server.certificate);
const freePort = () => {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = listener.addr.port;
  listener.close();
  return port;
};
const port = freePort(), managementPort = freePort();
let challenges = 0;
const responder = Deno.serve(
  { hostname: "127.0.0.1", port: 0, onListen() {} },
  async (request) => {
    const url = new URL(request.url);
    if (url.pathname === "/probe") {
      return new Response(
        request.headers.get("host") === "example.test" ? "proof" : "wrong",
      );
    }
    if (url.pathname === "/redirect") {
      return new Response(null, {
        status: 302,
        headers: { Location: "/probe" },
      });
    }
    const token = url.pathname.slice("/.well-known/acme-challenge/".length);
    const value = await getChallenge(url.hostname, "acme", token);
    if (value) challenges++;
    return new Response(value ?? "", { status: value ? 200 : 404 });
  },
);
await Deno.writeTextFile(
  `${root}/pebble.json`,
  JSON.stringify({
    pebble: {
      listenAddress: `127.0.0.1:${port}`,
      managementListenAddress: `127.0.0.1:${managementPort}`,
      certificate: certificateFile,
      privateKey: privateFile,
      httpPort: responder.addr.port,
      tlsPort: freePort(),
      keyAlgorithm: "ecdsa",
      retryAfter: { authz: 1, order: 1 },
      profiles: {
        default: { validityPeriod: 7776000 },
        shortlived: { validityPeriod: 576000 },
      },
    },
  }),
);
const log = await Deno.open(`${root}/pebble.log`, {
  create: true,
  write: true,
});
const child = new Deno.Command(pebble, {
  args: ["-config", `${root}/pebble.json`],
  env: {
    GOMAXPROCS: "2",
    GOMEMLIMIT: "128MiB",
    PEBBLE_VA_NOSLEEP: "1",
    PEBBLE_WFE_NONCEREJECT: "0",
    PEBBLE_ALTERNATE_ROOTS: "0",
    PEBBLE_VA_ALWAYS_VALID: "0",
  },
  stdout: "piped",
  stderr: "inherit",
}).spawn();
const logging = child.stdout.pipeTo(log.writable);
const limit = setTimeout(() => child.kill("SIGKILL"), 120000);
const agent = new Agent({ ca: fixtures.server.certificate });
axios.defaults.httpsAgent = agent;
const directory = `https://127.0.0.1:${port}/dir`;
try {
  let ready = false;
  let newOrderEndpoint = "";
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      const response = await axios.get(directory);
      if (response.status === 200) {
        newOrderEndpoint = response.data.newOrder;
        ready = true;
        break;
      }
    } catch { /* The child has not opened its listener yet. */ }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert(ready, "Pebble did not start");
  assert(
    await probeAddress(
      "127.0.0.1",
      "example.test",
      "/probe",
      "proof",
      AbortSignal.timeout(2000),
      responder.addr.port,
    ),
  );
  assertEquals(
    await probeAddress(
      "127.0.0.1",
      "example.test",
      "/redirect",
      "proof",
      AbortSignal.timeout(2000),
      responder.addr.port,
    ),
    false,
  );
  const config = await saveConfiguration({
    ...await getConfiguration(),
    directory,
    ipAddress: "127.0.0.1",
  });
  const first = await beginOperation("127.0.0.1");
  assert(first.status === "claimed");
  await admitName("127.0.0.1", first.token);
  fixture.failSQL = 'insert into "the8020__https__challenges"';
  await assertRejects(() =>
    obtainCertificate("127.0.0.1", first.token, config)
  );
  fixture.failSQL = undefined;
  const interrupted = await Certificates.selectAll().where(
    "name",
    "=",
    "127.0.0.1",
  ).executeTakeFirstOrThrow();
  assert(
    interrupted.orderState?.order?.url,
    "Order was not saved before interruption",
  );
  const account = await Accounts.selectAll().executeTakeFirstOrThrow();
  let resumedOrders = 0;
  const interceptor = axios.interceptors.request.use((request) => {
    if (request.url === newOrderEndpoint) resumedOrders++;
    return request;
  });
  await Certificates.update({ claimUntil: new Date(0) }).where(
    "name",
    "=",
    "127.0.0.1",
  ).execute();
  const resumed = await beginOperation("127.0.0.1");
  assert(resumed.status === "claimed" && resumed.admitted);
  await obtainCertificate("127.0.0.1", resumed.token, config);
  axios.interceptors.request.eject(interceptor);
  assertEquals(resumedOrders, 0, "Recovery created another ACME order");
  assert(challenges > 0, "Pebble did not actually validate HTTP-01");
  assertEquals((await Accounts.selectAll().execute()).length, 1);
  assertEquals(
    (await Accounts.selectAll().executeTakeFirstOrThrow()).keySecret,
    account.keySecret,
  );
  const state = await snapshot();
  assertEquals(state.certificates.length, 1);
  assert(state.certificates[0]!.domains.includes("127.0.0.1"));
  assertEquals((await beginOperation("127.0.0.1")).status, "ready");
  assertEquals(
    (await Certificates.selectAll().executeTakeFirstOrThrow()).orderState,
    null,
  );
  console.log(
    "Pebble HTTP-01 issuance, saved-order recovery, account reuse, short-lived IP certificate, and pinned reachability checks passed",
  );
} finally {
  clearTimeout(limit);
  child.kill("SIGTERM");
  await child.status;
  await logging;
  agent.destroy();
  await responder.shutdown();
  fixture.close();
}
