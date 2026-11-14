// Sampan relayer, testnet (M5). Listens on 127.0.0.1 only; one route: POST /register.
//   node apps/relayer/src/server.ts
// Env: NEAR_TESTNET_ACCOUNT_ID (parent), NEAR_TESTNET_PRIVATE_KEY (in memory only),
// RELAYER_PORT (default 8790), RELAYER_ORIGIN (the shop page origin allowed by CORS).
// The relayer account is merchant.<parent>: it only pays refundable deposits (see policy.ts).
// A mainnet relayer is a separate account with its own key and a small balance, set up by a
// person; this file refuses anything but testnet.
import { createServer } from "node:http";
import { Account, JsonRpcProvider } from "near-api-js";
import { assertTestnet, redact, testnetKeyFromEnv, installRedactingErrorHandlers } from "../../../scripts/m1/safety.mjs";
import { handle, Limits, MAX_BODY_BYTES, Sweeper, type Policy, type Registrar } from "./policy.ts";
import { verifySignedMandate, toBytes } from "@sampan/mandate";

installRedactingErrorHandlers();
const RPC = "https://rpc.testnet.near.org";
const parent = process.env.NEAR_TESTNET_ACCOUNT_ID ?? "";
const ACC = { gate: `gate-m3.${parent}`, token: `token.${parent}`, relayer: `merchant.${parent}`, shop: `payee2-m3.${parent}` };
assertTestnet({ networkId: "testnet", rpcUrl: RPC, accounts: [parent, ...Object.values(ACC)] });
const PORT = Number(process.env.RELAYER_PORT ?? 8790);
const ORIGIN = process.env.RELAYER_ORIGIN ?? "http://127.0.0.1:8791";

const provider = new JsonRpcProvider({ url: RPC });
const relayer = new Account(ACC.relayer, provider, testnetKeyFromEnv());
const view = (method: string, args = {}) => provider.callFunction({ contractId: ACC.gate, method, args }) as Promise<any>;
const cfg = await view("get_config");
const deposit = (2400n + BigInt(cfg.max_orders_per_mandate) * 450n) * 10n ** 19n + 2n * BigInt(cfg.registration_deposit);

const policy: Policy = {
  network: "testnet", gate: ACC.gate, asset: ACC.token, payees: new Set([ACC.shop]), maxPrice: 2_000_000n,
  // The widget builds 2-hour mandates; allow a little clock skew, never the gate's full 24 h (M5-03).
  maxLifetimeMs: Number(BigInt(cfg.max_lifetime_ns) / 1_000_000n), minLifetimeMs: 45 * 60_000, // capped further in checkMandate (M5-03)
};
const limits = new Limits(10, Math.max(1, Number(cfg.max_mandates) - 1));
// M5-03: close the relayer's expired mandates (refund pays refund_to; closing returns the deposit).
const sweeper = new Sweeper();
setInterval(async () => {
  for (const h of sweeper.due(Date.now())) {
    try {
      if ((await view("get_mandate", { mandate_hash: h })) === null) { sweeper.done(h); continue; }
      await relayer.callFunctionRaw({ contractId: ACC.gate, methodName: "refund", args: { mandate_hash: h }, gas: 100n * 10n ** 12n });
    } catch (e) {
      console.error(redact(String((e as Error)?.message ?? e)).slice(0, 120));
    }
  }
}, 60_000).unref();
const registrar: Registrar = {
  accountExists: async (account) => provider.viewAccount({ accountId: account, finality: "final" } as any).then(() => true, () => false),
  openMandates: async () => Number((await view("get_totals")).live_mandates), // A1R-01: only unexpired mandates hold a slot
  register: async (signedText) => {
    const r: any = await relayer.callFunctionRaw({ contractId: ACC.gate, methodName: "register_mandate", args: { signed_mandate: signedText }, deposit, gas: 30n * 10n ** 12n });
    const raw = r?.status?.SuccessValue ? Buffer.from(r.status.SuccessValue, "base64").toString("utf8") : "";
    try {
      const v = JSON.parse(JSON.parse(raw));
      console.log(redact(`register ${v.registered ? "ok" : "refused"} tx ${r.transaction.hash}`));
      if (v.registered === true) {
        const vm = verifySignedMandate(toBytes(signedText));
        sweeper.add(vm.mandateHash, Number(BigInt(vm.mandate.expiry_ns) / 1_000_000n));
      }
      return { registered: v.registered === true, reason: typeof v.reason === "string" ? v.reason : undefined };
    } catch {
      return { registered: false, reason: "refused" };
    }
  },
};

const headers = { "content-type": "application/json", "access-control-allow-origin": ORIGIN, "access-control-allow-methods": "POST", "access-control-allow-headers": "content-type", vary: "origin", "cache-control": "no-store" };
createServer((req, res) => {
  const send = (status: number, body: unknown) => { res.writeHead(status, headers); res.end(JSON.stringify(body)); };
  if (req.method === "OPTIONS") return send(204, {});
  if (req.method !== "POST" || req.url !== "/register") return send(404, { registered: false, reason: "not_found" });
  if (!String(req.headers["content-type"] ?? "").startsWith("application/json")) return send(415, { registered: false, reason: "json_only" });
  let size = 0;
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => {
    size += c.length;
    if (size > MAX_BODY_BYTES * 2) { send(413, { registered: false, reason: "too_large" }); req.destroy(); return; }
    chunks.push(c);
  });
  req.on("end", async () => {
    if (res.headersSent) return;
    let body: unknown;
    try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { return send(400, { registered: false, reason: "invalid" }); }
    try {
      const a = await handle(body, req.socket.remoteAddress ?? "?", { policy, limits, registrar, nowMs: Date.now() });
      send(a.status, a.body);
    } catch (e) {
      console.error(redact(String((e as Error)?.message ?? e)).slice(0, 200));
      send(502, { registered: false, reason: "gate_unavailable" });
    }
  });
}).listen(PORT, "127.0.0.1", () => console.log(`relayer on http://127.0.0.1:${PORT} for ${ACC.gate}, deposit ${deposit} yoctoNEAR`));
