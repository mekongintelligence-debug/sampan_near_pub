// Independent audit M6 (docs/audits/M6.md): exploit and regression tests for the checker
// logic. Each test asserts the REQUIRED behaviour, so it FAILS while its finding is open.
// Positive controls (marked) pass. They replay the recorded testnet answers in
// apps/checker/test/fixtures and patch them to model hostile or historical chain data.
// No network is used.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { verifyReceipt, type Result } from "./verify.ts";
import { checkRpcUrl } from "./rpc.ts";

const FIX = resolve(import.meta.dirname, "../test/fixtures");
const load = (name: string) => JSON.parse(readFileSync(resolve(FIX, `${name}.json`), "utf8"));
const release = load("release"), refuse = load("refuse");
const PRIMARY = "https://rpc.testnet.near.org";
const SECOND = "https://test.rpc.fastnear.com";
const GATE = "gate-m3.sampan-trust-01.testnet";
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const bytes = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
const status = (r: Result, id: string) => r.checks.find((c) => c.id === id)?.status;

type Rec = { method: string; params: any; response: any };
const recs: Rec[] = [...release.recorded, ...refuse.recorded];
const UNKNOWN = { jsonrpc: "2.0", id: "x", error: { name: "HANDLER_ERROR", cause: { name: "UNKNOWN_TRANSACTION" } } };
const ok = (result: unknown) => ({ jsonrpc: "2.0", id: "x", result });
const LOCKED = ok({ block_hash: "11111111111111111111111111111111", block_height: 276480993, keys: [] });
const FULL_ACCESS = ok({
  block_hash: "11111111111111111111111111111111", block_height: 276480993,
  keys: [{ access_key: { nonce: 1, permission: "FullAccess" }, public_key: "ed25519:4MTM1jjhjV9MUa9ArY4gTojue9hpWqnXS4pzjJGijrHD" }],
});

/**
 * A chain model built from the recorded answers. `answer` may override any request
 * (return undefined to fall through). By default the gate's access-key list is empty
 * (a locked account) and any historical query (`block_id`) is unknown.
 */
type Answer = (method: string, params: any, recorded: any | undefined) => any | undefined;
function chain(answer: Answer = () => undefined) {
  return async (_url: string, init: { body: string }) => {
    const req = JSON.parse(init.body);
    const rec = recs.find((r) => r.method === req.method && JSON.stringify(r.params) === JSON.stringify(req.params));
    const custom = answer(req.method, req.params, rec ? clone(rec.response) : undefined);
    if (custom !== undefined) return { ok: true, json: async () => custom };
    if (rec) return { ok: true, json: async () => clone(rec.response) };
    if (req.method === "query" && req.params?.request_type === "view_access_key_list" && req.params?.finality === "final") return { ok: true, json: async () => LOCKED };
    return { ok: true, json: async () => UNKNOWN };
  };
}
async function run(envelope: unknown, primary: Answer = () => undefined, opts: { second?: Answer; secondUrl?: string } = {}): Promise<Result> {
  const p = chain(primary), s = chain(opts.second ?? (() => undefined));
  const secondUrl = opts.secondUrl ?? (opts.second ? SECOND : undefined);
  const fetchFn = async (url: string, init: any) => (new URL(url).hostname === new URL(SECOND).hostname ? s(url, init) : p(url, init));
  return verifyReceipt(bytes(envelope), { rpcUrl: PRIMARY, secondRpcUrl: secondUrl, fetchFn: fetchFn as any });
}
const isTx = (m: string) => m === "tx" || m === "EXPERIMENTAL_tx_status";

describe("positive controls (pass today and must keep passing)", () => {
  it("control: the recorded release verifies", async () => {
    expect((await run(release.envelope)).overall).toBe("verified");
  });
  it("control: the recorded refusal verifies", async () => {
    expect((await run(refuse.envelope)).overall).toBe("verified");
  });
  it("control: an honest second RPC on another host agrees", async () => {
    const r = await run(release.envelope, undefined, { second: () => undefined });
    expect(status(r, "second-rpc")).toBe("pass");
  });
});

// ---- M6-01 (High): the gate account's key holder can forge a green receipt -------------
// The live gate-m3.sampan-trust-01.testnet holds a FullAccess key (view_access_key_list,
// 6 Nov 2026). With it, anyone holding the key can deploy unreviewed code, have it write a
// receipt record (payout "Done") and emit a "receipt" event, then redeploy the reviewed
// wasm. The checker only compares the CURRENT code hash with the reviewed list, so the
// forged receipt passes every check although no token moved.
describe("M6-01 receipts written by unreviewed code on the known gate account", () => {
  it("M6-01 a gate account that holds a full-access key does not give a plain Verified", async () => {
    const r = await run(release.envelope, (m, p) => (m === "query" && p.request_type === "view_access_key_list" ? FULL_ACCESS : undefined));
    expect(r.overall).not.toBe("verified");
  });

  it("M6-01 deploy-call-deploy in one batch on the gate (event from unreviewed code) is not green", async () => {
    // One transaction signed with the gate's own key: DeployContract(evil), FunctionCall
    // (writes the record and emits the event), DeployContract(reviewed). Afterwards the
    // key is deleted, so the account even looks locked at `final`.
    const r = await run(release.envelope, (m, _p, rec) => {
      if (!isTx(m) || !rec) return undefined;
      const t = rec.result.transaction;
      t.signer_id = GATE; t.receiver_id = GATE;
      t.actions = [
        { DeployContract: { code: "evil-wasm-sha256" } },
        { FunctionCall: { method_name: "forge", args: "e30=", gas: 100000000000000, deposit: "0" } },
        { DeployContract: { code: "reviewed-wasm-sha256" } },
      ];
      return rec;
    });
    expect(r.overall).not.toBe("verified");
  });

  it("M6-01 the gate ran different code at the decision block (redeployed since) is not green", async () => {
    // Separate transactions: deploy evil code, let the agent's ordinary purchase hit it,
    // redeploy the reviewed build, delete the key. At `final` everything looks reviewed and
    // locked; at the decision block the code (and keys) were different.
    const r = await run(release.envelope, (m, p) => {
      if (m !== "query" || p.block_id === undefined) return undefined;
      if (p.request_type === "view_account") return ok({ amount: "1", block_hash: "1", block_height: 1, code_hash: "EvilCodeHash1111111111111111111111111111111", locked: "0", storage_paid_at: 0, storage_usage: 1 });
      if (p.request_type === "view_access_key_list") return FULL_ACCESS;
      return undefined;
    });
    expect(r.overall).not.toBe("verified");
  });
});

// ---- M6-02 (Medium): the second RPC cross-check is partial and can be the same host ----
describe("M6-02 the second-RPC cross-check", () => {
  it("M6-02 the primary RPC host given again as the 'second RPC' is not shown as an independent cross-check", async () => {
    const r = await run(release.envelope, undefined, { secondUrl: PRIMARY });
    expect(status(r, "second-rpc")).not.toBe("pass");
  });
  it("M6-02 a second RPC that reports other gate code is a disagreement, not green", async () => {
    const r = await run(release.envelope, undefined, { second: (m, p, rec) => (m === "query" && p.request_type === "view_account" && rec ? (rec.result.code_hash = "11111111111111111111111111111111", rec) : undefined) });
    expect(r.overall).not.toBe("verified");
  });
  it("M6-02 a second RPC that says the decision transaction is not final is a disagreement, not green", async () => {
    const r = await run(release.envelope, undefined, { second: (m, _p, rec) => (isTx(m) && rec ? (rec.result.final_execution_status = "EXECUTED_OPTIMISTIC", rec) : undefined) });
    expect(r.overall).not.toBe("verified");
  });
  it("M6-02 a second RPC whose event core differs from the file is a disagreement, not green", async () => {
    const r = await run(release.envelope, undefined, { second: (m, _p, rec) => {
      if (!isTx(m) || !rec) return undefined;
      for (const o of rec.result.receipts_outcome) o.outcome.logs = o.outcome.logs.map((l: string) => l.replace('"decision":"release"', '"decision":"refuse"'));
      return rec;
    } });
    expect(r.overall).not.toBe("verified");
  });
});

// ---- M6-06 (Medium): envelope transaction hashes other than `decision` are never checked
describe("M6-06 every transaction hash in the envelope is checked", () => {
  it("M6-06 a payout hash that is some other transaction (here: another order's refusal) is not green", async () => {
    const e = clone(release.envelope);
    e.tx.payout = refuse.envelope.tx.decision;
    expect((await run(e)).overall).not.toBe("verified");
  });
  it("M6-06 a deposit hash that does not exist on chain is not green", async () => {
    const e = clone(release.envelope);
    e.tx.deposit = "11111111111111111111111111111111";
    expect((await run(e)).overall).not.toBe("verified");
  });
});

// ---- M6-08 (Info): the RPC allow-list in code accepts any port and path ----------------
describe("M6-08 RPC URL allow-list", () => {
  it("M6-08 a non-default port on an allowed host is refused (the CSP refuses it anyway)", () => {
    expect(() => checkRpcUrl("https://rpc.testnet.near.org:8443/")).toThrow();
  });
});

// ---- M6-10 (Info): RPC-supplied text reaches the page verbatim and unbounded ------------
describe("M6-10 RPC-supplied text", () => {
  it("M6-10 an RPC error name is not shown verbatim at any length", async () => {
    const long = "Verified by NEAR. ".repeat(5000);
    const r = await run(release.envelope, (m) => (m === "status" ? { jsonrpc: "2.0", id: "x", error: { name: long } } : undefined));
    expect(r.overall).toBe("unverifiable"); // control: never green
    for (const c of r.checks) expect(c.detail.length, c.id).toBeLessThanOrEqual(400);
  });
});
