import { assertEquals } from "@std/assert";
import { DatabaseSync } from "node:sqlite";
import {
  kernelDatabaseBackendSymbol,
  type KernelInvoke,
  kernelInvokeSymbol,
} from "@the8020/kernel";
import type { ExecutionContext } from "@the8020/context";
import { installContextProvider } from "../../kernel/defaults/config/runtime/deno/context/runtime.ts";
import { createTableSQL } from "/p/the8020/db/internal/ddl.ts";

const globals = globalThis as unknown as Record<symbol, unknown>;
globals[kernelDatabaseBackendSymbol] = "sqlite";
const { descriptorOf } = await import("/p/the8020/db/mod.ts");
const tables = await Promise.all([
  import("../tables/configuration.ts"),
  import("../tables/versions.ts"),
  import("../tables/certificates.ts"),
  import("../tables/challenges.ts"),
  import("../tables/accounts.ts"),
  import("../tables/authority.ts"),
  import("/p/the8020/secrets/tables/secrets.ts"),
  import("/p/the8020/system/tables/revisions.ts"),
]);

/** Real package SQL/codecs with an isolated SQLite engine and a test encryption key. */
export async function testDatabase() {
  const database = new DatabaseSync(":memory:");
  database.exec("PRAGMA foreign_keys=ON");
  for (const table of tables) {
    database.exec(createTableSQL("sqlite", descriptorOf(table.default)));
  }
  const restore = installContextProvider(
    () => ({
      username: "system",
      authenticated: true,
      nodeId: "nod-test",
    } as ExecutionContext),
  );
  const previous = globals[kernelInvokeSymbol];
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  const fixture = {
    database,
    failSQL: undefined as string | undefined,
    close() {
      globals[kernelInvokeSymbol] = previous;
      restore();
      database.close();
    },
  };
  globals[kernelInvokeSymbol] = (async (operation, input) => {
    if (operation.startsWith("database.transaction.")) {
      const action = operation.split(".").at(-1)!;
      database.exec(action === "begin" ? "BEGIN" : action.toUpperCase());
      return { transaction: "transaction" };
    }
    if (operation === "database.execute") {
      const text = String(input.statement);
      if (fixture.failSQL && text.startsWith(fixture.failSQL)) {
        throw new Error("injected database failure");
      }
      const parameters = (input.parameters as unknown[]).map((value) => {
        if (value !== null && typeof value === "object") {
          const tagged = value as { type: string; value: unknown };
          return tagged.type === "boolean"
            ? Number(tagged.value)
            : tagged.type === "json"
            ? JSON.stringify(tagged.value)
            : tagged.value;
        }
        return typeof value === "boolean" ? Number(value) : value;
      }) as Array<string | number | null>;
      const statement = database.prepare(text);
      if (input.return_rows) {
        const rows = statement.all(...parameters),
          columns = statement.columns().map((column) => column.name);
        return {
          columns,
          rows: rows.map((row) => columns.map((column) => row[column])),
        };
      }
      return {
        columns: [],
        rows: [],
        affected_rows: {
          type: "bigint",
          value: String(statement.run(...parameters).changes),
        },
      };
    }
    assertEquals(operation, "runtime.operation");
    const args = input.input as {
      purpose: string;
      data: string;
      encrypted: string;
      associated_data: string;
    };
    if (
      input.operation === "crypto.encrypt" ||
      input.operation === "crypto.decrypt"
    ) {
      assertEquals(args.purpose, "app-secret-store");
      const additionalData = Uint8Array.fromBase64(args.associated_data);
      if (input.operation === "crypto.encrypt") {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = new Uint8Array(
          await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData },
            key,
            Uint8Array.fromBase64(args.data),
          ),
        );
        return {
          success: true,
          result: {
            encrypted: "test:" +
              new Uint8Array([...iv, ...encrypted]).toBase64(),
          },
        };
      }
      const bytes = Uint8Array.fromBase64(args.encrypted.slice(5));
      const data = new Uint8Array(
        await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: bytes.slice(0, 12), additionalData },
          key,
          bytes.slice(12),
        ),
      );
      return { success: true, result: { data: data.toBase64() } };
    }
    throw new Error("node publication unavailable");
  }) satisfies KernelInvoke;
  return fixture;
}
