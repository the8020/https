import { assert, assertEquals } from "@std/assert";
import { type KernelInvoke, kernelInvokeSymbol } from "@the8020/kernel";
import { testDatabase } from "../../src/test_database.ts";
import fixtures from "../../src/certificate_fixtures.json" with {
  type: "json",
};
import { clientCertificate } from "/p/the8020/users/src/certificate_fixtures.ts";
import { X509Certificate } from "node:crypto";

interface Browser {
  evaluate<T>(expression: string): Promise<T>;
  command(method: string, params?: Record<string, unknown>): Promise<unknown>;
}

export default async function fixture() {
  const database = await testDatabase();
  const { descriptorOf } = await import("/p/the8020/db/mod.ts");
  const { createTableSQL } = await import("/p/the8020/db/internal/ddl.ts");
  for (const name of ["users", "sessions", "certificates"]) {
    const table = (await import(`/p/the8020/users/tables/${name}.ts`)).default;
    database.database.exec(createTableSQL("sqlite", descriptorOf(table)));
  }
  const { default: Users } = await import("/p/the8020/users/tables/users.ts");
  await Users.insert({
    username: "caller",
    fullName: "Service caller",
    passwordHash: "",
    enabled: true,
    authVersion: 1,
    createdAt: new Date(),
    updatedAt: new Date(),
  }).execute();
  const { default: https } = await import("./program.ts");
  const { userDetail } = await import(
    "/p/the8020/users/programs/users/program.ts"
  );
  const { listCertificates } = await import(
    "/p/the8020/users/src/certificates.ts"
  );
  const { getConfiguration } = await import("../../src/configuration.ts");
  const { certificateRecords } = await import("../../src/admin.ts");
  const { callScreen, Model, presentPage, z } = await import(
    "/p/the8020/uui/mod.ts"
  );
  const globals = globalThis as unknown as Record<symbol, unknown>;
  const invoke = globals[kernelInvokeSymbol] as KernelInvoke;
  let failApplication = true;
  let applied = 0;
  globals[kernelInvokeSymbol] = ((operation, input) => {
    if (operation === "runtime.operation" && input.operation === "node.list") {
      return Promise.resolve({
        success: true,
        result: {
          nodes: [{
            node: { id: "nod-local" },
            capacity: {
              https: {
                desired_revision: applied + 1,
                applied_revision: applied,
                ready: true,
                error: "Injected publication failure",
              },
            },
          }, {
            node: { id: "nod-offline" },
            error: "Node is unreachable",
          }],
        },
      });
    }
    if (operation === "admin.execute") {
      const desired = Number(
        database.database.prepare(
          "SELECT revision FROM the8020__system__revisions WHERE domain = ?",
        ).get("index:the8020/https")?.revision ?? 0,
      );
      if (input.command_id === "kernel.reindex") {
        if (failApplication) {
          return Promise.resolve({
            success: false,
            error: { message: "Injected publication failure" },
          });
        }
        applied = desired;
        return Promise.resolve({ success: true, result: {} });
      }
    }
    return invoke(operation, input);
  }) satisfies KernelInvoke;
  return {
    serve() {
      return Promise.resolve(undefined);
    },
    close() {
      database.close();
      return Promise.resolve();
    },
    async run() {
      while (true) {
        const event = await callScreen({
          id: "certificate-fixture",
          title: "Certificate administration",
          schema: z.object({}),
          model: new Model({}),
          header: {
            actions: [{ id: "https", label: "HTTPS" }, {
              id: "user",
              label: "User",
            }],
          },
        });
        if (event.action === "https") await presentPage(https);
        if (event.action === "user") {
          await presentPage(() => userDetail("caller", true));
        }
      }
    },
    async verify(page: Browser) {
      const wait = async (expression: string) => {
        const until = Date.now() + 10000;
        while (!await page.evaluate(expression)) {
          if (Date.now() > until) throw new Error(`Timed out: ${expression}`);
          await new Promise((resolve) => setTimeout(resolve, 25));
        }
      };
      const visible =
        "!item.closest('[inert],[hidden]') && item.getClientRects().length > 0";
      const title = (value: string) =>
        wait(
          `[...document.querySelectorAll('.screen')].some(item => ${visible} && item.querySelector(':scope > .screen-title')?.textContent === ${
            JSON.stringify(value)
          })`,
        );
      const button = (label: string) =>
        wait(
          `(() => { const item = [...document.querySelectorAll('button')].find(item => ${visible} && !item.disabled && (item.textContent.trim() === ${
            JSON.stringify(label)
          } || item.getAttribute('aria-label') === ${
            JSON.stringify(label)
          })); if (!item) return false; item.click(); return true; })()`,
        );
      const input = (bind: string, value: string) =>
        wait(
          `(() => { const item = [...document.querySelectorAll('[data-bind="${bind}"]')].find(item => ${visible}); if (!item) return false; item.value = ${
            JSON.stringify(value)
          }; item.dispatchEvent(new Event('input', {bubbles:true})); item.dispatchEvent(new Event('change', {bubbles:true})); return true; })()`,
        );
      const row = (name: string) =>
        wait(
          `(() => { const item = [...document.querySelectorAll('.data-list tbody tr')].find(item => ${visible} && item.textContent.includes(${
            JSON.stringify(name)
          })); if (!item) return false; item.click(); return true; })()`,
        );
      const upload = async (id: string, bytes: Uint8Array, name: string) => {
        await wait(
          `document.querySelector('[data-element-id=${id}] input[type=file]') !== null`,
        );
        await page.evaluate(
          `(() => { const input = document.querySelector('[data-element-id=${id}] input[type=file]'); const files = new DataTransfer(); files.items.add(new File([new Uint8Array(${
            JSON.stringify(Array.from(bytes))
          })], ${
            JSON.stringify(name)
          })); input.files = files.files; input.dispatchEvent(new Event('change', {bubbles:true})); })()`,
        );
        await wait(
          `!document.querySelector('[data-element-id=${id}] input[type=file]').disabled`,
        );
      };
      const cancelPicker = async (id: string) => {
        await wait(
          `!!document.querySelector('[data-element-id=${id}] input[type=file]')`,
        );
        assert(
          await page.evaluate<boolean>(`(() => {
          const input = document.querySelector('[data-element-id=${id}] input[type=file]');
          const dialog = input.closest('dialog');
          input.dispatchEvent(new Event('cancel', { bubbles: true }));
          return dialog.open && !dialog.inert && input.isConnected;
        })()`),
          "Cancelling the file picker must keep the upload modal active",
        );
      };
      await button("HTTPS");
      await title("HTTPS");
      assertEquals((await getConfiguration()).allowedDomains, ["*"]);
      await button("Add domain");
      await title("Add domain");
      await input("name", "a.*.test");
      await button("Done");
      await wait(
        "document.body.textContent.includes('Enter a hostname, *.domain, or *')",
      );
      await title("Add domain");
      await input("name", "*.Example.TEST");
      await button("Done");
      await title("HTTPS");
      await input("attemptsPerHour", "5");
      await button("Save");
      await wait(
        "document.body.textContent.includes('Saved; node application failed')",
      );
      assertEquals((await getConfiguration()).attemptsPerHour, 5);
      assertEquals((await getConfiguration()).allowedDomains, [
        "*",
        "*.example.test",
      ]);
      await button("Advanced");
      await title("Advanced HTTPS");
      await input("directory", "https://acme.test/directory");
      await button("Add proxy");
      await title("Add proxy");
      await input("peer", "127.0.0.1/32");
      await button("Done");
      await title("Advanced HTTPS");
      await button("Node diagnostics");
      await title("Node HTTPS diagnostics");
      await wait(
        "document.body.textContent.includes('Injected publication failure')",
      );
      await wait("document.body.textContent.includes('Node is unreachable')");
      await button("Back");
      await title("Advanced HTTPS");
      await button("Done");
      await title("HTTPS");
      assertEquals((await getConfiguration()).trustedProxies, []);
      failApplication = false;
      await button("Save");
      await wait(
        "document.body.textContent.includes('Saved and applied on this node')",
      );
      assertEquals((await getConfiguration()).trustedProxies, ["127.0.0.1/32"]);
      assertEquals(
        (await getConfiguration()).directory,
        "https://acme.test/directory",
      );
      await button("Certificates");
      await title("HTTPS certificates");
      await button("Upload certificate");
      await title("Upload certificate");
      await input("name", "example.test");
      await cancelPicker("chain");
      await upload(
        "chain",
        new TextEncoder().encode(fixtures.server.certificate),
        "server.crt",
      );
      await cancelPicker("key");
      await upload(
        "key",
        new TextEncoder().encode(fixtures.replacement.key),
        "wrong.key",
      );
      await button("Save");
      await wait(
        "document.body.textContent.includes('Certificate and private key do not match')",
      );
      assertEquals(await certificateRecords(), []);
      await upload(
        "chain",
        new TextEncoder().encode(fixtures.server.certificate),
        "server.crt",
      );
      await upload(
        "key",
        new TextEncoder().encode(fixtures.server.key),
        "server.key",
      );
      await button("Save");
      await title("HTTPS certificates");
      assertEquals((await certificateRecords())[0]?.status, "Ready");
      assert(
        !await page.evaluate<boolean>(
          "document.body.textContent.includes('BEGIN PRIVATE KEY')",
        ),
      );
      await row("example.test");
      await title("example.test");
      await button("Replace certificate");
      await title("Replace certificate");
      await upload(
        "chain",
        new TextEncoder().encode(fixtures.replacement.certificate),
        "replacement.crt",
      );
      await upload(
        "key",
        new TextEncoder().encode(fixtures.replacement.key),
        "replacement.key",
      );
      await button("Save");
      await title("example.test");
      assertEquals(
        (await certificateRecords())[0]?.fingerprint,
        new X509Certificate(fixtures.replacement.certificate).fingerprint256
          .replaceAll(":", "").toLowerCase(),
      );
      await button("Back");
      await title("HTTPS certificates");
      await button("Back");
      await title("HTTPS");
      await button("Back");
      await title("Certificate administration");
      await button("User");
      await title("My account");
      await button("Certificates");
      await title("Certificates · caller");
      await button("Add certificate");
      await title("Add certificate");
      await input("label", "API client");
      await upload(
        "file",
        new TextEncoder().encode(clientCertificate),
        "client.pem",
      );
      await button("Add certificate");
      await title("Certificates · caller");
      assertEquals((await listCertificates("caller")).length, 1);
      await row("API client");
      await title("API client");
      await button("Remove certificate");
      await title("Remove certificate?");
      await button("Remove certificate");
      await title("Certificates · caller");
      assertEquals((await listCertificates("caller")).length, 0);
      await page.command("Emulation.setDeviceMetricsOverride", {
        width: 390,
        height: 844,
        deviceScaleFactor: 1,
        mobile: true,
      });
      await button("Add certificate");
      await title("Add certificate");
      await input("label", "DER client");
      await upload(
        "file",
        new X509Certificate(clientCertificate).raw,
        "client.der",
      );
      await button("Add certificate");
      await title("Certificates · caller");
      assertEquals((await listCertificates("caller"))[0]?.label, "DER client");
    },
  };
}
