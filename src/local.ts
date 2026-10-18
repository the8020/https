import { createPrivateKey } from "node:crypto";
import { Buffer } from "node:buffer";
import { isIP } from "node:net";
import { newId } from "@the8020/kernel";
import { transaction } from "/p/the8020/db/mod.ts";
import { getSecret, setSecret } from "/p/the8020/secrets/mod.ts";
// @deno-types="../vendor/x509.ts"
import {
  AuthorityKeyIdentifierExtension,
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  SubjectKeyIdentifierExtension,
  X509Certificate,
  X509CertificateGenerator,
} from "../vendor/x509.js";
import Authority from "../tables/authority.ts";
import { publishCertificate } from "./certificates.ts";

const generateKey = () =>
  crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
async function keyPEM(key: CryptoKey): Promise<string> {
  const der = Buffer.from(await crypto.subtle.exportKey("pkcs8", key));
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" })
    .export({ format: "pem", type: "pkcs8" }).toString();
}

async function authority() {
  const stored = await Authority.selectAll().where("id", "=", "local")
    .executeTakeFirst();
  if (stored) return stored;
  const keys = await generateKey(), now = Date.now();
  const certificate = await X509CertificateGenerator.createSelfSigned({
    name: "CN=80|20 Local HTTPS CA",
    keys,
    notBefore: new Date(now - 60000),
    notAfter: new Date(now + 10 * 365 * 86400000),
    extensions: [
      new BasicConstraintsExtension(true, 0, true),
      new KeyUsagesExtension(
        KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign,
        true,
      ),
      await SubjectKeyIdentifierExtension.create(keys.publicKey),
    ],
  });
  const key = await keyPEM(keys.privateKey),
    keySecret = `https-authority-${newId("key")}`;
  return await transaction({ timeoutMs: 2000 }, async (tx) => {
    const inserted = await tx.insertInto(Authority.table).values({
      id: "local",
      certificate: certificate.toString("pem"),
      keySecret,
      expiresAt: certificate.notAfter,
    }).onConflict((conflict) => conflict.column("id").doNothing())
      .returningAll().executeTakeFirst();
    if (inserted) {
      await setSecret({ name: keySecret, value: key }, tx);
      return inserted;
    }
    return await tx.selectFrom(Authority.table).selectAll().where(
      "id",
      "=",
      "local",
    ).executeTakeFirstOrThrow();
  });
}

/** Local issuance shares the ordinary per-name claim; it has no external order. */
export async function obtainLocalCertificate(name: string, token: string) {
  const stored = await authority();
  const root = new X509Certificate(stored.certificate), now = Date.now();
  if (root.notBefore.getTime() > now || root.notAfter.getTime() <= now) {
    throw new Error(
      "The local HTTPS authority is not valid; replace it before issuing local certificates",
    );
  }
  const rootPublicKey = await root.publicKey.export();
  const rootKey = createPrivateKey((await getSecret(stored.keySecret)).value);
  const signingKey = await crypto.subtle.importKey(
    "jwk",
    rootKey.export({ format: "jwk" }),
    rootPublicKey.algorithm,
    false,
    ["sign"],
  );
  const keys = await generateKey();
  const certificate = await X509CertificateGenerator.create({
    subject: `CN=${name}`,
    issuer: root.subjectName,
    publicKey: keys.publicKey,
    signingKey,
    notBefore: new Date(Math.max(now - 60000, root.notBefore.getTime())),
    notAfter: new Date(Math.min(now + 12 * 3600000, root.notAfter.getTime())),
    extensions: [
      new BasicConstraintsExtension(false, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
      new ExtendedKeyUsageExtension(["1.3.6.1.5.5.7.3.1"]),
      new SubjectAlternativeNameExtension([{
        type: isIP(name) ? "ip" : "dns",
        value: name,
      }]),
      await SubjectKeyIdentifierExtension.create(keys.publicKey),
      await AuthorityKeyIdentifierExtension.create(root.publicKey),
    ],
  });
  return await publishCertificate(
    name,
    `${certificate.toString("pem")}\n${stored.certificate}`,
    await keyPEM(keys.privateKey),
    token,
  );
}
