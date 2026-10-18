import { createHash, X509Certificate } from "node:crypto";
import { newId } from "@the8020/kernel";
import { requirePermission } from "/p/the8020/auth/mod.ts";
import { transaction, z } from "/p/the8020/db/mod.ts";
import { setSecret } from "/p/the8020/secrets/mod.ts";
import {
  invalidateIndexes,
  lockIndexRevision,
} from "/p/the8020/system/src/indexes.ts";
import Accounts from "../tables/accounts.ts";
import Authority from "../tables/authority.ts";
import Certificates from "../tables/certificates.ts";
import Configuration from "../tables/configuration.ts";
import Versions from "../tables/versions.ts";
import { certificate } from "../types/certificate.ts";
import { normalizeHostname, policy } from "../types/policy.ts";
import { getConfiguration, packageId } from "./configuration.ts";
import {
  inspectAuthority,
  inspectPrivateKey,
  inspectServerCertificate,
} from "./validation.ts";
import { localNames, publicName } from "./reachability.ts";

const legacyState = z.object({
  configuration: policy,
  attempts: z.array(z.int().nonnegative()).max(10000),
  admitted: z.array(z.string().max(253)).max(10000),
  authority: z.object({ certificate: z.string(), key: z.string() }).strict()
    .nullable(),
  accounts: z.array(
    z.object({
      directory: policy.shape.directory,
      accountUrl: z.url().max(2048),
      email: policy.shape.email,
      key: z.string(),
    }).strict(),
  ).max(16),
  certificates: z.array(
    z.object({
      name: certificate.shape.name,
      source: certificate.shape.source,
      chain: z.string(),
      key: z.string(),
    }).strict(),
  ).max(100),
}).strict();

/** Import once before exposing native TLS; a retry never replaces renewed state. */
export async function importLegacyState(raw: string) {
  await requirePermission("https.configuration.edit", "");
  if (new TextEncoder().encode(raw).length > 256 * 1024) {
    throw new Error(
      "HTTPS migration input exceeds 256 KiB; retain the old deployment and migrate explicitly",
    );
  }
  const digest = createHash("sha256").update(raw).digest("hex");
  const imported = await Configuration.select([Configuration.legacyImport])
    .where("id", "=", "https").executeTakeFirst();
  if (imported?.legacyImport) {
    if (imported.legacyImport !== digest) {
      throw new Error("A different HTTPS migration has already completed");
    }
    return { imported: false };
  }
  let input: unknown;
  try {
    input = JSON.parse(raw);
  } catch {
    throw new TypeError("Invalid HTTPS migration JSON");
  }
  const data = legacyState.parse(input);
  const admitted = [...new Set(data.admitted.map((name) => publicName(name)))];
  const root = data.authority &&
    inspectAuthority(data.authority.certificate, data.authority.key);
  const rootCertificate = root && new X509Certificate(root.certificate);
  const accounts = data.accounts.map((account) => {
    inspectPrivateKey(account.key);
    if (new URL(account.accountUrl).protocol !== "https:") {
      throw new Error("Unsupported ACME account URL");
    }
    return {
      ...account,
      id: createHash("sha256").update(account.directory).digest("hex"),
    };
  });
  if (new Set(accounts.map((account) => account.id)).size !== accounts.length) {
    throw new Error("Migration requires one account per ACME directory");
  }
  const local = localNames(data.configuration.ipAddress);
  const certificates = data.certificates.map((record) => {
    const inspected = inspectServerCertificate(
      record.name,
      record.chain,
      record.key,
      true,
    );
    if (
      record.source === "local" && (!root || !local.includes(inspected.name))
    ) {
      throw new Error(
        "Local certificates require their original CA and a configured local name",
      );
    }
    if (record.source === "local") {
      const end = new X509Certificate(
        inspected.chain.match(
          /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g,
        )!.at(-1)!,
      );
      if (
        end.issuer !== rootCertificate!.subject ||
        !end.verify(rootCertificate!.publicKey)
      ) {
        throw new Error(
          "Local certificate chain does not lead to the imported authority",
        );
      }
    }
    if (record.source === "acme") {
      publicName(inspected.name);
      if (
        inspected.domains.length !== 1 ||
        inspected.name !== normalizeHostname(inspected.name) ||
        local.includes(inspected.name)
      ) {
        throw new Error(
          "Automatic migration supports single-name ACME certificates",
        );
      }
      if (!admitted.includes(inspected.name)) admitted.push(inspected.name);
    }
    return { ...record, inspected };
  });
  if (
    new Set(certificates.map((record) => record.inspected.name)).size !==
      certificates.length
  ) {
    throw new Error("Migration contains competing certificates for one name");
  }
  for (const record of certificates) {
    await requirePermission("https.certificate.edit", record.inspected.name);
  }
  await getConfiguration();
  return await transaction({ timeoutMs: 10000 }, async (tx) => {
    await lockIndexRevision(tx);
    const current = await tx.updateTable(Configuration.table).set({
      updatedAt: new Date(),
    })
      .where("id", "=", "https").returningAll().executeTakeFirstOrThrow();
    if (current.legacyImport) {
      if (current.legacyImport !== digest) {
        throw new Error("A different HTTPS migration has already completed");
      }
      return { imported: false };
    }
    if (
      JSON.stringify(policy.parse(current.value)) !==
        JSON.stringify(policy.parse({})) || current.attempts.length
    ) {
      throw new Error(
        "HTTPS configuration has already changed; migration cannot overwrite it",
      );
    }
    for (const table of [Certificates.table, Authority.table, Accounts.table]) {
      if (await tx.selectFrom(table).selectAll().limit(1).executeTakeFirst()) {
        throw new Error(
          "HTTPS certificates or accounts already exist; migration cannot overwrite them",
        );
      }
    }
    if (root && data.authority) {
      const keySecret = `https-authority-${newId("key")}`;
      await setSecret({ name: keySecret, value: data.authority.key }, tx);
      await tx.insertInto(Authority.table).values({
        id: "local",
        ...root,
        keySecret,
      }).execute();
    }
    for (const account of accounts) {
      const { key, ...metadata } = account,
        keySecret = `https-account-${newId("key")}`;
      await setSecret({ name: keySecret, value: key }, tx);
      await tx.insertInto(Accounts.table).values({ ...metadata, keySecret })
        .execute();
    }
    for (const record of certificates) {
      const id = newId("crt"),
        keySecret = `https-${id}`,
        inspected = record.inspected;
      await setSecret({ name: keySecret, value: record.key }, tx);
      await tx.insertInto(Versions.table).values({
        ...inspected,
        id,
        keySecret,
        createdAt: new Date(),
      }).execute();
      await tx.insertInto(Certificates.table).values({
        name: inspected.name,
        source: record.source,
        activeVersion: id,
        admitted: admitted.includes(inspected.name),
        dueAt: record.source === "provided" ? null : new Date(
          inspected.validFrom.getTime() +
            (inspected.expiresAt.getTime() - inspected.validFrom.getTime()) *
              2 / 3,
        ),
      }).execute();
    }
    for (const name of admitted) {
      await tx.insertInto(Certificates.table).values({
        name,
        source: "acme",
        admitted: true,
        dueAt: new Date(),
      })
        .onConflict((conflict) => conflict.column("name").doNothing())
        .execute();
    }
    await tx.updateTable(Configuration.table).set({
      value: data.configuration,
      attempts: data.attempts,
      legacyImport: digest,
    }).where("id", "=", "https").execute();
    await invalidateIndexes(tx, [packageId]);
    return { imported: true };
  });
}
