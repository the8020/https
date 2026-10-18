import { field, z } from "/p/the8020/db/fields.ts";
import { domainToASCII } from "node:url";
import { isIP } from "node:net";

export function normalizeHostname(input: string): string {
  if (!input || /[\s/\\@?#%\[\]]/.test(input)) {
    throw new TypeError("Invalid hostname");
  }
  if (isIP(input) === 6) {
    const address = new URL(`http://[${input}]`).hostname.slice(1, -1);
    if (address.startsWith("::ffff:")) {
      const words = address.slice(7).split(":").map((word) =>
        parseInt(word, 16)
      );
      return words.flatMap((word) => [word >> 8, word & 255]).join(".");
    }
    return address;
  }
  if (isIP(input) === 4) return input;
  const name = domainToASCII(input.endsWith(".") ? input.slice(0, -1) : input)
    .toLowerCase();
  if (
    name.length === 0 || name.length > 253 || isIP(name) !== 0 ||
    !name.split(".").every((label) =>
      /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
    )
  ) throw new TypeError("Invalid hostname");
  if (new URL(`http://${name}`).hostname !== name) {
    throw new TypeError("Use an unambiguous hostname or canonical IP address");
  }
  return name;
}

export function normalizePattern(input: string): string {
  if (input === "*") return input;
  if (input.startsWith("*.")) {
    const name = normalizeHostname(input.slice(2));
    if (isIP(name) || !name.includes(".")) {
      throw new TypeError("A wildcard must precede a DNS domain");
    }
    return `*.${name}`;
  }
  return normalizeHostname(input);
}

export function covers(pattern: string, name: string): boolean {
  return pattern === "*" || pattern === name ||
    (!isIP(name) && pattern.startsWith("*.") &&
      name.includes(".") &&
      name.slice(name.indexOf(".") + 1) === pattern.slice(2));
}

export const domainPattern = field(
  z.string().max(255).transform((value, ctx) => {
    try {
      return normalizePattern(value);
    } catch {
      ctx.addIssue({
        code: "custom",
        message: "Enter a hostname, *.domain, or *",
      });
      return z.NEVER;
    }
  }),
  {
    label: "Allowed domain",
    description:
      "An exact hostname, * for any eligible name, or *.example.com for one additional DNS label.",
  },
);

export const policy = z.object({
  enabled: field(z.boolean().default(true), {
    label: "HTTPS",
    description:
      "Enable the kernel's HTTPS listener with centrally managed certificates.",
  }),
  letsEncrypt: field(z.boolean().default(true), {
    label: "Let's Encrypt",
    description:
      "Automatically obtain and renew certificates for admitted names using HTTP-01 validation.",
  }),
  allowedDomains: field(z.array(domainPattern).max(1000).default(["*"]), {
    label: "Allowed domains",
    description:
      "Names admitted on the managed public ingress. An empty list denies public names.",
    storage: { type: "json" },
  }),
  attemptsPerHour: field(z.int().min(0).max(10000).default(2), {
    label: "New hostname attempts per hour",
    description:
      "System-wide rolling-hour enrollment allowance. Failed checks consume an attempt. Zero pauses new enrollment.",
  }),
  maximumNames: field(z.int().min(0).max(10000).default(10), {
    label: "Maximum admitted hostnames",
    description:
      "System-wide enrollment limit. Lowering it retains existing names and renewals.",
  }),
  concurrentChecks: field(z.int().min(0).max(100).default(2), {
    label: "Concurrent admission checks",
    description:
      "Maximum simultaneous new-name checks across all nodes. Zero pauses new enrollment.",
  }),
  checkTimeoutSeconds: field(z.number().min(0.1).max(30).default(3), {
    label: "Admission timeout (seconds)",
    description: "Combined DNS and HTTP reachability-check deadline.",
  }),
  directory: field(
    z.url().max(2048).refine((value) => {
      const url = new URL(value);
      return url.protocol === "https:" && !url.username && !url.password &&
        !url.hash;
    }, "Use an HTTPS ACME directory URL").default(
      "https://acme-v02.api.letsencrypt.org/directory",
    ),
    {
      label: "ACME directory",
      description:
        "Directory used for new ACME orders; existing account identities remain associated with their directory.",
    },
  ),
  email: field(z.union([z.email(), z.literal("")]).default(""), {
    label: "Account email",
    description: "Contact address for the ACME account.",
  }),
  challengeFallback: field(
    z.union([
      z.literal(""),
      z.url().max(2048).refine((value) => {
        const url = new URL(value);
        return ["http:", "https:"].includes(url.protocol) && !url.username &&
          !url.password && !url.search && !url.hash && url.pathname === "/";
      }, "Use an HTTP or HTTPS origin without credentials or a path"),
    ]).default(""),
    {
      label: "Challenge fallback",
      description:
        "Another system sharing this public HTTP endpoint, such as the production instance in a dev/prod deployment. Consulted only when no local certificate challenge matches; no certificates or keys are copied.",
    },
  ),
  ipAddress: field(
    z.string().transform((value, ctx) => {
      if (value === "") return value;
      try {
        if (isIP(value)) return normalizeHostname(value);
      } catch { /* Report field validation below. */ }
      ctx.addIssue({ code: "custom", message: "Enter an IP address" });
      return z.NEVER;
    }).default(""),
    {
      label: "HTTPS IP address",
      description:
        "Configured IP identity, including clients that do not send SNI.",
    },
  ),
  trustedProxies: field(
    z.array(
      z.string().transform((value, ctx) => {
        const [address, prefix, extra] = value.split("/");
        const version = isIP(address ?? "");
        if (
          extra === undefined && version !== 0 && !value.includes("%") &&
          (prefix === undefined ||
            /^\d+$/.test(prefix) &&
              Number(prefix) <= (version === 4 ? 32 : 128))
        ) {
          const normalized = normalizeHostname(address!);
          const bits = prefix === undefined ? undefined : Number(prefix) -
            (version === 6 && isIP(normalized) === 4 ? 96 : 0);
          if (bits === undefined) return normalized;
          if (bits >= 0) return `${normalized}/${bits}`;
        }
        ctx.addIssue({
          code: "custom",
          message: "Enter an IP address or CIDR network",
        });
        return z.NEVER;
      }),
    ).max(100).default([]),
    {
      label: "Trusted certificate proxies",
      description:
        "Backend peers allowed to assert RFC 9440 Client-Cert. The protected backend must be reachable only by trusted terminators, which must replace incoming certificate headers.",
      storage: { type: "json" },
    },
  ),
}).strict();

export type Policy = z.infer<typeof policy>;
