import { text } from "/p/the8020/i18n/mod.ts";
import { msg } from "/p/the8020/https/i18n/messages.ts";
import Accounts from "../../tables/accounts.ts";
import Authority from "../../tables/authority.ts";
import Certificates from "../../tables/certificates.ts";
import Versions from "../../tables/versions.ts";

const open = { program: "the8020/https/https", arguments: [] };

/** Secret usages for `the8020/secrets`: private keys owned by HTTPS. */
export default async function secretUsages(names: string[]) {
  if (!Array.isArray(names) || names.length === 0) return [];
  const wanted = new Set(names);
  const usages = [];
  for (
    const row of await Accounts.select([Accounts.keySecret, Accounts.email])
      .where(Accounts.keySecret, "in", names).limit(1000).execute()
  ) {
    usages.push({
      secret: row.keySecret,
      title: text(msg("secret_usages.acme_account")),
      detail: row.email,
      open,
    });
  }
  for (
    const row of await Authority.select([Authority.keySecret])
      .where(Authority.keySecret, "in", names).limit(1000).execute()
  ) {
    usages.push({
      secret: row.keySecret,
      title: text(msg("secret_usages.local_certificate_authority")),
      open,
    });
  }
  for (
    const row of await Versions.select([Versions.keySecret, Versions.name])
      .where(Versions.keySecret, "in", names).limit(1000).execute()
  ) {
    usages.push({
      secret: row.keySecret,
      title: text(msg("secret_usages.certificate_name", { name: row.name })),
      detail: text(msg("secret_usages.private_key")),
      open,
    });
  }
  // Pending orders keep their key inside the JSON order state.
  for (
    const row of await Certificates.select([
      Certificates.name,
      Certificates.orderState,
    ]).where(Certificates.orderState, "is not", null).limit(1000).execute()
  ) {
    if (row.orderState && wanted.has(row.orderState.keySecret)) {
      usages.push({
        secret: row.orderState.keySecret,
        title: text(msg("secret_usages.certificate_name", { name: row.name })),
        detail: text(msg("secret_usages.pending_order_key")),
        open,
      });
    }
  }
  return usages;
}
