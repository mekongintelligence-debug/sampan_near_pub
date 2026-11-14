// Independent audit A2 (docs/audits/A2.md): checker exploit tests. Each "A2-NN ..." test
// asserts the REQUIRED behaviour, so it FAILS while its finding is open. "control: ..." tests
// pass now and must keep passing. Recorded testnet answers from apps/checker/test/fixtures are
// replayed and patched; no network is used.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { verifyReceipt, type Result } from "./verify.ts";
import { KNOWN_GATES } from "./gates.ts";

const FIX = resolve(import.meta.dirname, "../test/fixtures");
const load = (name: string) => JSON.parse(readFileSync(resolve(FIX, `${name}.json`), "utf8"));
const release = load("release");
const clone = <T>(x: T): T => JSON.parse(JSON.stringify(x));
const bytes = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
const ok = (result: unknown) => ({ jsonrpc: "2.0", id: "x", result });
const err = (cause: string) => ({ jsonrpc: "2.0", id: "x", error: { name: "HANDLER_ERROR", cause: { name: cause } } });
const LOCKED = ok({ block_hash: "11111111111111111111111111111111", block_height: 276480993, keys: [] });
const FULL = { access_key: { nonce: 1, permission: "FullAccess" }, public_key: "ed25519:4MTM1jjhjV9MUa9ArY4gTojue9hpWqnXS4pzjJGijrHD" };

type Answer = (method: string, params: any) => any | undefined;
/** Recorded answers; the gate is locked NOW (final key list empty). `historic` answers block_id queries. */
function run(historic: Answer): Promise<Result> {
  const recs: { method: string; params: any; response: any }[] = release.recorded;
  const fetchFn = async (_url: string, init: { body: string }) => {
    const req = JSON.parse(init.body);
    const p = req.params;
    let body: any;
    if (req.method === "query" && p?.block_id !== undefined) body = historic(req.method, p);
    else if (req.method === "query" && p?.request_type === "view_access_key_list") body = LOCKED;
    if (body === undefined) {
      const rec = recs.find((r) => r.method === req.method && JSON.stringify(r.params) === JSON.stringify(p));
      body = rec ? clone(rec.response) : err("UNKNOWN_TRANSACTION");
    }
    return { ok: true, json: async () => body };
  };
  return verifyReceipt(bytes(release.envelope), { rpcUrl: "https://rpc.testnet.near.org", fetchFn: fetchFn as any });
}
const check = (r: Result, id: string) => r.checks.find((c) => c.id === id);
const codeHash = () => (release.recorded as any[]).find((r) => r.params?.request_type === "view_account").response.result.code_hash as string;

// ---- A2-01 (Medium): "The gate ran reviewed code when it decided" disappears without history --
// The gate's key holder can, before the lock, deploy other code, have it write a receipt record
// and emit a receipt event in a transaction signed by another account, redeploy the reviewed
// build, and lock later (runbook step 6 releases BEFORE the lock). After the lock, the current
// state is clean. Only the historic check can tell. When the RPC cannot answer for the decision
// block (garbage collected, shard not tracked), historicGate() returns null and verify.ts drops
// the check entirely, so the receipt reads "Verified".
describe("A2-01 a receipt decided while the gate may still have had an owner key", () => {
  it("control: with history showing reviewed code and no key in the decision block, it verifies", async () => {
    const r = await run((_m, p) => (p.request_type === "view_account" ? ok({ code_hash: codeHash(), amount: "0" }) : LOCKED));
    expect(check(r, "then")?.status).toBe("pass");
    expect(r.overall).toBe("verified");
  });
  it("control: with history showing an owner key in the decision block, it is not verified", async () => {
    const r = await run((_m, p) => (p.request_type === "view_account" ? ok({ code_hash: codeHash(), amount: "0" }) : ok({ keys: [FULL] })));
    expect(r.overall).not.toBe("verified");
  });
  for (const cause of ["GARBAGE_COLLECTED_BLOCK", "UNAVAILABLE_SHARD", "UNKNOWN_BLOCK"]) {
    it(`A2-01 when the RPC answers ${cause} for the decision block, the check is shown and the receipt is not plain Verified`, async () => {
      const r = await run(() => err(cause));
      // Required: never drop the check silently. Either prove the decision came after the
      // recorded lock height of the known gate, or show the check as "Cannot verify".
      expect(check(r, "then")).toBeDefined();
      expect(r.overall).not.toBe("verified");
    });
  }
});

// ---- A2F-02 (Low): a decision in the lock block itself is ambiguous ------------------------------
describe("A2F-02 lock block boundary", () => {
  const h = release.envelope.core.block_height as number;
  const gate = KNOWN_GATES.testnet[0]!;
  const withLock = async (lock: number) => {
    const old = gate.lockedAtBlock;
    gate.lockedAtBlock = lock;
    try { return await run(() => err("GARBAGE_COLLECTED_BLOCK")); } finally { gate.lockedAtBlock = old; }
  };
  it("A2F-02 a decision in the same block as the lock is not shown as passed", async () => {
    expect(check(await withLock(h), "then")?.status).toBe("unknown");
  });
  it("A2F-02 a decision in a block after the lock passes (control)", async () => {
    expect(check(await withLock(h - 1), "then")?.status).toBe("pass");
  });
  it("A2F-02 a decision before the lock is not shown as passed", async () => {
    expect(check(await withLock(h + 1), "then")?.status).toBe("unknown");
  });
});
