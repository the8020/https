import { text } from "/p/the8020/i18n/mod.ts";
import { msg } from "/p/the8020/https/i18n/messages.ts";
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
        message: text(msg("validation.hostname")),
      });
      return z.NEVER;
    }
  }),
  {
    label: msg("policy.allowed_domain"),
    description: msg("policy.an_exact_hostname_for_any_eligible_name"),
  },
);

export const policy = z.object({
  enabled: field(z.boolean().default(true), {
    label: msg("program.https"),
    description: msg("policy.enable_the_kernel_s_https_listener_with"),
  }),
  letsEncrypt: field(z.boolean().default(true), {
    label: msg("policy.let_s_encrypt"),
    description: msg(
      "policy.automatically_obtain_and_renew_certificates_for_admitted",
    ),
  }),
  allowedDomains: field(z.array(domainPattern).max(1000).default(["*"]), {
    label: msg("program.allowed_domains"),
    description: msg("policy.names_admitted_on_the_managed_public_ingress"),
    storage: { type: "json" },
  }),
  attemptsPerHour: field(z.int().min(0).max(10000).default(2), {
    label: msg("policy.new_hostname_attempts_per_hour"),
    description: msg(
      "policy.system_wide_rolling_hour_enrollment_allowance_failed",
    ),
  }),
  maximumNames: field(z.int().min(0).max(10000).default(10), {
    label: msg("policy.maximum_admitted_hostnames"),
    description: msg("policy.system_wide_enrollment_limit_lowering_it_retains"),
  }),
  concurrentChecks: field(z.int().min(0).max(100).default(2), {
    label: msg("policy.concurrent_admission_checks"),
    description: msg("policy.maximum_simultaneous_new_name_checks_across_all"),
  }),
  checkTimeoutSeconds: field(z.number().min(0.1).max(30).default(3), {
    label: msg("policy.admission_timeout_seconds"),
    description: msg(
      "policy.combined_dns_and_http_reachability_check_deadline",
    ),
  }),
  directory: field(
    z.url().max(2048).refine((value) => {
      const url = new URL(value);
      return url.protocol === "https:" && !url.username && !url.password &&
        !url.hash;
    }, { error: () => text(msg("validation.acme")) }).default(
      "https://acme-v02.api.letsencrypt.org/directory",
    ),
    {
      label: msg("policy.acme_directory"),
      description: msg("policy.directory_used_for_new_acme_orders_existing"),
    },
  ),
  email: field(z.union([z.email(), z.literal("")]).default(""), {
    label: msg("policy.account_email"),
    description: msg("policy.contact_address_for_the_acme_account"),
  }),
  challengeFallback: field(
    z.union([
      z.literal(""),
      z.url().max(2048).refine((value) => {
        const url = new URL(value);
        return ["http:", "https:"].includes(url.protocol) && !url.username &&
          !url.password && !url.search && !url.hash && url.pathname === "/";
      }, { error: () => text(msg("validation.origin")) }),
    ]).default(""),
    {
      label: msg("policy.challenge_fallback"),
      description: msg(
        "policy.another_system_sharing_this_public_http_endpoint",
      ),
    },
  ),
  ipAddress: field(
    z.string().transform((value, ctx) => {
      if (value === "") return value;
      try {
        if (isIP(value)) return normalizeHostname(value);
      } catch { /* Report field validation below. */ }
      ctx.addIssue({ code: "custom", message: text(msg("validation.ip")) });
      return z.NEVER;
    }).default(""),
    {
      label: msg("policy.https_ip_address"),
      description: msg(
        "policy.configured_ip_identity_including_clients_that_do",
      ),
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
          message: text(msg("validation.network")),
        });
        return z.NEVER;
      }),
    ).max(100).default([]),
    {
      label: msg("advanced.trusted_certificate_proxies"),
      description: msg("policy.backend_peers_allowed_to_assert_rfc_9440"),
      storage: { type: "json" },
    },
  ),
}).strict();

export type Policy = z.infer<typeof policy>;
