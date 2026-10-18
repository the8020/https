import { AsyncLocalStorage } from "node:async_hooks";
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { newId } from "@the8020/kernel";
import { transaction } from "/p/the8020/db/mod.ts";
import { deleteSecret, getSecret, setSecret } from "/p/the8020/secrets/mod.ts";
// @deno-types="../vendor/acme.ts"
import acme from "../vendor/acme.cjs";
import { acmeOrder, type OrderState } from "../types/acme.ts";
import type { Policy } from "../types/policy.ts";
import Accounts from "../tables/accounts.ts";
import Certificates from "../tables/certificates.ts";
import { putChallenge, removeChallenges } from "./challenges.ts";
import { publishCertificate } from "./certificates.ts";
import { admitName, beginOperation, failOperation } from "./operations.ts";
import { verifyReachability } from "./reachability.ts";
import { obtainLocalCertificate } from "./local.ts";
import { normalizeHostname } from "../types/policy.ts";

const { axios, Client, crypto: acmeCrypto } = acme;
const requests = new AsyncLocalStorage<
  { signal: AbortSignal; retryAfter?: Date }
>();
axios.defaults.timeout = 15000;
axios.defaults.maxContentLength = 256 * 1024;
axios.defaults.maxBodyLength = 128 * 1024;
// Persist CA delays in the shared operation instead of sleeping inside an expiring claim.
Object.assign(axios.defaults, {
  acmeSettings: { retryMaxAttempts: 0, retryDefaultDelay: 5 },
});
axios.interceptors.request.use((config) => {
  const scope = requests.getStore();
  if (scope) config.signal = scope.signal;
  return config;
});
axios.interceptors.response.use((response) => {
  const scope = requests.getStore();
  if (scope && response.status >= 400) {
    const header = response.headers["retry-after"];
    if (typeof header === "string") {
      const time = /^\d+$/.test(header)
        ? Date.now() + Number(header) * 1000
        : Date.parse(header);
      if (
        Number.isFinite(time) && time > Date.now() &&
        !Number.isNaN(new Date(time).getTime())
      ) {
        scope.retryAfter = new Date(time);
      }
    }
  }
  return response;
});

async function account(directory: string, email: string) {
  const id = createHash("sha256").update(directory).digest("hex");
  let stored = await Accounts.selectAll().where("id", "=", id)
    .executeTakeFirst();
  if (!stored) {
    const value = (await acmeCrypto.createPrivateEcdsaKey()).toString();
    const keySecret = `https-account-${newId("key")}`;
    stored = await transaction({ timeoutMs: 2000 }, async (tx) => {
      const inserted = await tx.insertInto(Accounts.table).values({
        id,
        directory,
        keySecret,
        accountUrl: null,
        email: "",
        createdAt: new Date(),
      })
        .onConflict((conflict) => conflict.column("id").doNothing())
        .returningAll().executeTakeFirst();
      if (inserted) {
        await setSecret({ name: keySecret, value }, tx);
        return inserted;
      }
      return await tx.selectFrom(Accounts.table).selectAll().where(
        "id",
        "=",
        id,
      ).executeTakeFirstOrThrow();
    });
  }
  if (stored.directory !== directory) {
    throw new Error("ACME account identity mismatch");
  }
  const client = new Client({
    directoryUrl: directory,
    accountKey: (await getSecret(stored.keySecret)).value,
    accountUrl: stored.accountUrl ?? undefined,
    backoffAttempts: 30,
    backoffMin: 1000,
    backoffMax: 5000,
  });
  const contact = email ? [`mailto:${email}`] : [];
  if (!stored.accountUrl) {
    await client.createAccount({ termsOfServiceAgreed: true, contact });
    await Accounts.update({ accountUrl: client.getAccountUrl(), email }).where(
      "id",
      "=",
      id,
    ).execute();
  } else if (stored.email !== email) {
    await client.updateAccount({ contact });
    await Accounts.update({ email }).where("id", "=", id).execute();
  }
  return client;
}

async function prepareOrder(
  name: string,
  token: string,
  configuration: Policy,
): Promise<OrderState> {
  const current = await Certificates.select([Certificates.orderState]).where(
    "name",
    "=",
    name,
  )
    .where("claimToken", "=", token).where("claimUntil", ">", new Date())
    .executeTakeFirstOrThrow();
  if (current.orderState) return current.orderState;
  const key = await acmeCrypto.createPrivateEcdsaKey();
  const [, csr] = await acmeCrypto.createCsr({ altNames: [name] }, key);
  const state: OrderState = {
    directory: configuration.directory,
    keySecret: `https-order-${newId("key")}`,
    csr: csr.toString(),
    order: null,
  };
  return await transaction({ timeoutMs: 2000 }, async (tx) => {
    const owner = await tx.updateTable(Certificates.table).set({
      updatedAt: new Date(),
    })
      .where("name", "=", name).where("claimToken", "=", token).where(
        "claimUntil",
        ">",
        new Date(),
      )
      .returning("orderState").executeTakeFirstOrThrow();
    if (owner.orderState) return owner.orderState;
    await setSecret({ name: state.keySecret, value: key.toString() }, tx);
    await tx.updateTable(Certificates.table).set({ orderState: state }).where(
      "name",
      "=",
      name,
    ).execute();
    return state;
  });
}

async function rememberOrder(name: string, token: string, state: OrderState) {
  const changed = await Certificates.update({
    orderState: state,
    updatedAt: new Date(),
  })
    .where("name", "=", name).where("claimToken", "=", token).where(
      "claimUntil",
      ">",
      new Date(),
    ).executeTakeFirst();
  if (changed.numUpdatedRows !== 1n) {
    throw new Error("Certificate operation claim expired");
  }
}

async function discardOrder(name: string, token: string) {
  await transaction({ timeoutMs: 2000 }, async (tx) => {
    const owner = await tx.updateTable(Certificates.table).set({
      updatedAt: new Date(),
    })
      .where("name", "=", name).where("claimToken", "=", token).where(
        "claimUntil",
        ">",
        new Date(),
      )
      .returning("orderState").executeTakeFirstOrThrow();
    if (owner.orderState) await deleteSecret(owner.orderState.keySecret, tx);
    await tx.updateTable(Certificates.table).set({ orderState: null }).where(
      "name",
      "=",
      name,
    ).execute();
  });
}

/** Called after admission, with persisted order/key state and a fenced owner. */
export async function obtainCertificate(
  name: string,
  token: string,
  configuration: Policy,
) {
  const state = await prepareOrder(name, token, configuration);
  const client = await account(state.directory, configuration.email);
  state.order = acmeOrder.parse(
    state.order
      ? await client.getOrder(state.order)
      : await client.createOrder({
        identifiers: [{ type: isIP(name) ? "ip" : "dns", value: name }],
        ...(isIP(name) ? { profile: "shortlived" } : {}),
      }),
  );
  await rememberOrder(name, token, state);
  if (
    state.order.status === "invalid" ||
    state.order.expires && Date.parse(state.order.expires) <= Date.now()
  ) {
    await discardOrder(name, token);
    throw new Error(
      "ACME order expired or became invalid; a later attempt will create a new order",
    );
  }
  if (state.order.status === "pending") {
    const authorizations = await client.getAuthorizations(state.order);
    for (const authorization of authorizations) {
      if (authorization.identifier.value.toLowerCase() !== name) {
        throw new Error("ACME authorization name mismatch");
      }
      if (authorization.status === "valid") continue;
      const challenge = authorization.challenges.find((item) =>
        item.type === "http-01"
      );
      if (!challenge) {
        throw new Error("ACME provider did not offer HTTP-01 validation");
      }
      await putChallenge(
        name,
        token,
        "acme",
        challenge.token,
        await client.getChallengeKeyAuthorization(challenge),
      );
      if (challenge.status === "pending") {
        await client.completeChallenge(challenge);
      }
      await client.waitForValidStatus(challenge);
    }
    await client.waitForValidStatus(state.order);
    state.order = acmeOrder.parse(await client.getOrder(state.order));
    await rememberOrder(name, token, state);
  }
  if (state.order.status === "ready") {
    state.order = acmeOrder.parse(
      await client.finalizeOrder(state.order, state.csr),
    );
    await rememberOrder(name, token, state);
  }
  const chain = await client.getCertificate(state.order);
  const key = (await getSecret(state.keySecret)).value;
  return await publishCertificate(name, chain, key, token);
}

export async function issueCertificate(
  name: string,
  renew = false,
  signal?: AbortSignal,
) {
  signal?.throwIfAborted();
  name = normalizeHostname(name);
  const claim = await beginOperation(name, renew);
  if (claim.status !== "claimed") return claim;
  const controller = new AbortController();
  const timer = setTimeout(
    () => controller.abort(new Error("Certificate operation timed out")),
    Math.max(0, claim.deadline.getTime() - Date.now()),
  );
  const scope: { signal: AbortSignal; retryAfter?: Date } = {
    signal: signal
      ? AbortSignal.any([signal, controller.signal])
      : controller.signal,
  };
  return await requests.run(scope, async () => {
    try {
      scope.signal.throwIfAborted();
      if (claim.source === "local") {
        const certificate = await obtainLocalCertificate(name, claim.token);
        return { status: "issued" as const, certificate };
      }
      if (!claim.admitted) {
        await verifyReachability(
          name,
          claim.token,
          claim.configuration.checkTimeoutSeconds,
        );
        await admitName(name, claim.token);
      }
      scope.signal.throwIfAborted();
      const certificate = await obtainCertificate(
        name,
        claim.token,
        claim.configuration,
      );
      return { status: "issued" as const, certificate };
    } catch (error) {
      const message = error instanceof Error
        ? error.message
        : "Certificate operation failed";
      await failOperation(name, claim.token, message, scope.retryAfter);
      throw new Error(message);
    } finally {
      clearTimeout(timer);
      await removeChallenges(claim.token);
    }
  });
}
