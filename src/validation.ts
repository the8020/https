import {
  createHash,
  createPrivateKey,
  createPublicKey,
  X509Certificate as NativeCertificate,
} from "node:crypto";
// @deno-types="../vendor/x509.ts"
import {
  BasicConstraintsExtension,
  ExtendedKeyUsageExtension,
  fromBER,
  KeyUsageFlags,
  KeyUsagesExtension,
  SubjectAlternativeNameExtension,
  X509Certificate,
} from "../vendor/x509.js";
import { covers, normalizePattern } from "../types/policy.ts";

function parseChain(chain: string, allowExpired: boolean) {
  if (chain.length > 256 * 1024) {
    throw new TypeError("Certificate chain is too large");
  }
  const blocks = chain.match(
    /-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----/g,
  ) ?? [];
  if (
    blocks.length === 0 || blocks.length > 16 ||
    chain.replace(
      /-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----/g,
      "",
    ).trim()
  ) {
    throw new TypeError(
      "Provide a PEM leaf certificate followed by its intermediate chain",
    );
  }
  const parsed = blocks.map((block) => new X509Certificate(block));
  const native = blocks.map((block) => new NativeCertificate(block));
  const now = new Date();
  for (const cert of parsed) {
    if (fromBER(cert.rawData).offset !== cert.rawData.byteLength) {
      throw new TypeError("Certificate contains trailing DER data");
    }
    if (cert.notBefore > now || !allowExpired && cert.notAfter <= now) {
      throw new TypeError("Certificate chain is not currently valid");
    }
  }
  return { blocks, parsed, native };
}

export function inspectPrivateKey(key: string) {
  if (
    key.length > 65536 ||
    !/^\s*-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----[A-Za-z0-9+/=\s]+-----END \1-----\s*$/
      .test(key)
  ) {
    throw new TypeError(
      "Provide one unencrypted PEM private key (PKCS#8, RSA, or EC)",
    );
  }
  const privateKey = createPrivateKey(key);
  if (
    privateKey.asymmetricKeyType !== "rsa" &&
    privateKey.asymmetricKeyType !== "ec"
  ) {
    throw new TypeError("Use an RSA or ECDSA private key");
  }
  return privateKey;
}

function checkKey(certificate: NativeCertificate, key: string) {
  const privateKey = inspectPrivateKey(key);
  const publicKey = createPublicKey(privateKey).export({
    type: "spki",
    format: "der",
  });
  if (
    !publicKey.equals(
      certificate.publicKey.export({ type: "spki", format: "der" }),
    )
  ) {
    throw new TypeError("Certificate and private key do not match");
  }
}

export function inspectAuthority(certificate: string, key: string) {
  const { blocks, parsed, native } = parseChain(certificate, false);
  const root = parsed[0]!, signing = root.getExtension(KeyUsagesExtension);
  if (
    blocks.length !== 1 || !root.getExtension(BasicConstraintsExtension)?.ca ||
    signing && !(signing.usages & KeyUsageFlags.keyCertSign) ||
    native[0]!.issuer !== native[0]!.subject ||
    !native[0]!.verify(native[0]!.publicKey)
  ) {
    throw new TypeError("Provide one valid self-signed CA certificate");
  }
  checkKey(native[0]!, key);
  return { certificate: blocks[0]! + "\n", expiresAt: root.notAfter };
}

export function inspectServerCertificate(
  name: string,
  chain: string,
  key: string,
  allowExpired = false,
) {
  name = normalizePattern(name);
  if (name === "*") {
    throw new TypeError(
      "A certificate needs a concrete name or wildcard domain",
    );
  }
  const { blocks, parsed, native } = parseChain(chain, allowExpired);
  const leaf = parsed[0]!;
  if (leaf.getExtension(BasicConstraintsExtension)?.ca) {
    throw new TypeError("The leaf certificate must not be a CA");
  }
  const usage = leaf.getExtension(ExtendedKeyUsageExtension)?.usages;
  if (
    usage && !usage.includes("1.3.6.1.5.5.7.3.1") &&
    !usage.includes("2.5.29.37.0")
  ) {
    throw new TypeError("Certificate does not permit server authentication");
  }
  const signing = leaf.getExtension(KeyUsagesExtension);
  if (signing && !(signing.usages & KeyUsageFlags.digitalSignature)) {
    throw new TypeError("Certificate does not permit TLS signing");
  }
  const names = leaf.getExtension(SubjectAlternativeNameExtension)?.names.items
    .filter((item) => item.type === "dns" || item.type === "ip")
    .map((item) => normalizePattern(item.value)) ?? [];
  const domains = [...new Set(names)];
  if (
    domains.length === 0 || domains.length > 100 || domains.includes("*") ||
    !domains.some((domain) => covers(domain, name))
  ) {
    throw new TypeError("Certificate SANs do not cover its configured name");
  }
  for (let index = 1; index < native.length; index++) {
    if (
      !parsed[index]!.getExtension(BasicConstraintsExtension)?.ca ||
      native[index - 1]!.issuer !== native[index]!.subject ||
      !native[index - 1]!.verify(native[index]!.publicKey)
    ) {
      throw new TypeError("Certificate chain is not ordered leaf-to-issuer");
    }
  }
  checkKey(native[0]!, key);
  return {
    name,
    domains,
    fingerprint: createHash("sha256").update(new Uint8Array(leaf.rawData))
      .digest("hex"),
    chain: blocks.join("\n") + "\n",
    validFrom: leaf.notBefore,
    expiresAt: leaf.notAfter,
  };
}
