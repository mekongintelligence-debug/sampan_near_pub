// Independent audit M7 (docs/audits/M7.md): the gate as the last sender hint for the RPC
// `tx` lookup (M7 change in verify.ts). These are controls: they pass today and must keep
// passing. They show the hint only routes the lookup: a decision found through it is still
// checked in full, and one sent by the gate itself is still red (M6-01). Replays the recorded
// testnet answers in apps/checker/test/fixtures. No network is used.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { verifyReceipt, type Result } from "./verify.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { base58 } from "@scure/base";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalize, hashHex, nep413Hash, toBytes, verifySignedMandate } from "../../../packages/mandate/src/index.ts";

const FIX = resolve(import.meta.dirname, "../test/fixtures");
const release = JSON.parse(readFileSync(resolve(FIX, "release.json"), "utf8"));
const GATE = "gate-m3.sampan-trust-01.testnet";
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const status = (r: Result, id: string) => r.checks.find((c) => c.id === id)?.status;
const UNKNOWN = { jsonrpc: "2.0", id: "x", error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_TRANSACTION" } } };
const LOCKED = { jsonrpc: "2.0", id: "x", result: { block_hash: "11111111111111111111111111111111", block_height: 1, keys: [] } };

/** The recorded chain, except that a transaction is found only when the gate is the sender
 *  (as for a direct checkout sent by 1Click's account on an RPC that honours the hint). */
function chain(patchTx: (tx: any) => any = (t) => t, seen: string[] = []) {
  return async (_url: string, init: { body: string }) => {
    const req = JSON.parse(init.body);
    if (req.method === "tx") {
      seen.push(req.params.sender_account_id);
      const rec = release.recorded.find((r: any) => r.method === "tx" && r.params.tx_hash === req.params.tx_hash);
      if (!rec || req.params.sender_account_id !== GATE) return { ok: true, json: async () => UNKNOWN };
      const resp = clone(rec.response);
      resp.result = patchTx(resp.result);
      return { ok: true, json: async () => resp };
    }
    const rec = release.recorded.find((r: any) => r.method === req.method && JSON.stringify(r.params) === JSON.stringify(req.params));
    if (rec) return { ok: true, json: async () => clone(rec.response) };
    if (req.method === "query" && req.params?.request_type === "view_access_key_list" && req.params?.finality === "final") return { ok: true, json: async () => LOCKED };
    return { ok: true, json: async () => UNKNOWN };
  };
}
const run = (fetchFn: any) => verifyReceipt(new TextEncoder().encode(JSON.stringify(release.envelope)), { rpcUrl: "https://rpc.testnet.near.org", fetchFn });

describe("M7 sender hint (controls)", () => {
  it("control: a decision found only with the gate as sender is checked in full and can verify", async () => {
    const seen: string[] = [];
    const r = await run(chain(undefined, seen));
    expect(status(r, "tx")).toBe("pass");
    expect(r.overall).toBe("verified");
    // the gate is tried after the receipt's own accounts (agent, refund_to, buyer's implicit account)
    expect(seen.slice(0, 3)).not.toContain(GATE);
    expect(seen[3]).toBe(GATE);
  });
  it("control: a decision sent by the gate itself, found through the hint, is still red", async () => {
    const r = await run(chain((tx) => ({ ...tx, transaction: { ...tx.transaction, signer_id: GATE } })));
    expect(status(r, "tx")).toBe("fail");
    expect(r.overall).toBe("invalid");
  });
  it("control: a transaction found through the hint that lacks this receipt's event is red", async () => {
    const r = await run(chain((tx) => ({ ...tx, receipts_outcome: tx.receipts_outcome.map((o: any) => ({ ...o, outcome: { ...o.outcome, logs: [] } })) })));
    expect(status(r, "tx")).toBe("fail");
  });
});

// ---- SECURITY.md 6, M7 "and vice versa": a mainnet receipt checked on testnet -------------
// The author's test covers a testnet receipt against a mainnet RPC only. This builds a
// self-consistent mainnet receipt (fresh test key, no real account) and checks it against an
// RPC that reports testnet. Control: passes today.

describe("M7 cross-network replay at the checker (control)", () => {
  it("control: a mainnet receipt checked against a testnet RPC is never green", async () => {
    const sk = ed25519.utils.randomSecretKey();
    const gate = "gate.sampan-example.near", asset = "usdc-example.near", payee = "shop-example.near";
    const mandate = {
      v: "sampan.mandate.v1", network: "mainnet", gate, buyer: `near:ed25519:${base58.encode(ed25519.getPublicKey(sk))}`, agent: null, asset,
      max_amount: "1000000", payee, items: ["report-002"], expiry_ns: "1900000000000000000", nonce: "11".repeat(32), refund_to: "buyer-example.near",
    };
    const sig = ed25519.sign(nep413Hash(canonicalize(mandate), mandate.nonce, gate), sk);
    const signed = { v: "sampan.signed-mandate.v1", mandate, standard: "nep413", signature: bytesToHex(sig) };
    const mh = verifySignedMandate(toBytes(canonicalize(signed))).mandateHash;
    const order = { v: "sampan.order.v1", order_id: "22".repeat(32), mandate_hash: mh, item: "report-002", amount: "1000000", asset, payee };
    const core = {
      v: "sampan.receipt.v1", network: "mainnet", gate, mandate_hash: mh, order_hash: hashHex(canonicalize(order)), observed: { amount: "1000000", asset },
      rules: ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"].map((id) => ({ id, pass: true })), decision: "release", block_height: "1",
    };
    const h = base58.encode(new Uint8Array(32).fill(7));
    const env = { v: "sampan.receipt-envelope.v1", core, core_hash: hashHex(canonicalize(core)), signed_mandate: signed, order, tx: { deposit: null, decision: h, payout: null }, untrusted: null };
    const fetchFn = async (_u: string, init: { body: string }) => {
      const req = JSON.parse(init.body);
      if (req.method === "status") return { ok: true, json: async () => ({ jsonrpc: "2.0", id: "x", result: { chain_id: "testnet" } }) };
      return { ok: true, json: async () => UNKNOWN };
    };
    const r = await verifyReceipt(new TextEncoder().encode(JSON.stringify(env)), { rpcUrl: "https://rpc.testnet.near.org", fetchFn: fetchFn as any });
    expect(status(r, "file")).toBe("pass");
    expect(status(r, "network")).toBe("unknown");
    expect(r.overall).not.toBe("verified");
  });
});
