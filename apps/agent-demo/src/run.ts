#!/usr/bin/env node
// M4 scripted agent (no model). Started by the operator through scripts/m4/agent-env.mjs,
// as a separate OS user with no credentials in its environment (audit M4-02):
//   pnpm demo:attack   every labelled fixture: the agent submits the order written in the
//                      fixture, which models what a naive agent does after reading that page
//                      (the agent never parses page text, audit M4-09); the gate decides.
//                      Prints IDs, never page text.
//   pnpm demo:direct   the same function-call key tries every forbidden action.
//   node apps/agent-demo/src/run.ts probe --key <file>   one valid purchase (edge cases)
// Files: --key (function-call key), --state (public demo state), --out (results JSON);
// defaults are under .secrets/ and docs/ for direct runs.
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { Account, JsonRpcProvider, KeyPair } from "near-api-js";
import { loadFixtures, orderFor, type Fixture } from "./fixtures.ts";
import { assertAgentEnvironment, assertFunctionCallOnly, assertTestnetAccounts } from "./safety.ts";
import { redact, installRedactingErrorHandlers } from "../../../scripts/m1/safety.mjs";

installRedactingErrorHandlers(); // uncaught errors are printed redacted (audit M4-09)
assertAgentEnvironment(process.env); // first: the agent must not see operator secrets
const RPC = "https://rpc.testnet.near.org";
const ROOT = resolve(import.meta.dirname, "../../..");
const args = process.argv.slice(2);
const mode = args[0];
const opt = (name: string, dflt: string) => (args.includes(name) ? args[args.indexOf(name) + 1] : dflt);
const keyPath = opt("--key", resolve(ROOT, ".secrets/agent-fc.key"));
const outPath = (mode: string) => opt("--out", resolve(ROOT, `docs/m4-${mode}-results.json`));
const st = JSON.parse(readFileSync(opt("--state", resolve(ROOT, ".secrets/m4-state.json")), "utf8")) as Record<string, string>;
assertTestnetAccounts([st.gate, st.token, st.agent, st.payee, st.attacker]);
const keyText = readFileSync(keyPath, "utf8").trim();
const provider = new JsonRpcProvider({ url: RPC });
const pub = KeyPair.fromString(keyText as `ed25519:${string}`).getPublicKey().toString();
const link = (h: string) => `https://testnet.nearblocks.io/txns/${h}`;
const hex32 = () => randomBytes(32).toString("hex");
// One redactor for all scripts (M4-CR7); also hide public keys in printed errors.
const hide = (s: string) => redact(s).replace(/ed25519:[1-9A-HJ-NP-Za-km-z]{40,}/g, "ed25519:[key]");

type Outcome = { ok: boolean; tx: string; ret: unknown; error: string; logs: string[] };
async function send(fn: () => Promise<any>): Promise<Outcome> {
  try {
    const r = await fn();
    const tx = r?.transaction?.hash ?? "";
    const logs: string[] = (r?.receipts_outcome ?? []).flatMap((o: any) => o.outcome.logs);
    if (r?.status?.Failure) return { ok: false, tx, ret: null, error: hide(JSON.stringify(r.status.Failure)).slice(0, 300), logs };
    let ret: unknown = null;
    try { ret = JSON.parse(Buffer.from(r.status.SuccessValue ?? "", "base64").toString()); if (typeof ret === "string" && ret.startsWith("{")) ret = JSON.parse(ret); } catch { /* empty */ }
    return { ok: true, tx, ret, error: "", logs };
  } catch (e: any) {
    return { ok: false, tx: "", ret: null, error: hide(String(e?.message ?? e)).slice(0, 300), logs: [] };
  }
}

async function checkKey(allowMissing = false): Promise<void> {
  let view: any;
  try {
    view = await provider.query({ request_type: "view_access_key", finality: "final", account_id: st.agent, public_key: pub } as any);
  } catch (e: any) {
    // Only the edge-case probe may run with a key that no longer exists: the protocol refuses it.
    // Only the protocol's own "access key does not exist" answer counts (audit M4-04).
    if (allowMissing && /access key \S+ does not exist|UNKNOWN_ACCESS_KEY/i.test(String(e?.message ?? e))) return;
    throw e;
  }
  assertFunctionCallOnly(view, st.gate);
}

const agent = new Account(st.agent, provider, keyText as `ed25519:${string}`);
const purchase = (order: string) => send(() => agent.callFunctionRaw({ contractId: st.gate, methodName: "purchase", args: { order }, gas: 150n * 10n ** 12n }));

if (mode === "probe") {
  // One valid purchase with the key the operator handed over (edge cases). The key must
  // still be function-call only, unless it has been removed (M4-CR1).
  await checkKey(true);
  const r = await purchase(orderFor({ id: "ctl-00-probe", label: "control", proposes: { item: "report-001", payee: st.payee, amount: "1", asset: st.token }, expected: { decision: "release", failing: [] } }, st.mandateHash, hex32()));
  console.log("PROBE " + JSON.stringify({ ok: r.ok, tx: r.tx, ret: r.ret, error: r.error }));
  process.exit(0);
}

await checkKey();
console.log(`agent ${st.agent} holds a function-call key for ${st.gate}.purchase only (checked on chain)`);

/** Payout status of a release: from the payout event in the transaction, else the gate's view. */
async function payoutOf(r: Outcome, orderId: string): Promise<string> {
  const ev = r.logs.filter((l) => l.startsWith("EVENT_JSON:")).map((l) => JSON.parse(l.slice(11))).find((e) => e.event === "payout" && e.data?.[0]?.order_id === orderId);
  if (ev) return ev.data[0].status;
  for (let i = 0; i < 5; i++) {
    try {
      const v: any = await provider.callFunction({ contractId: st.gate, method: "get_receipt", args: { mandate_hash: st.mandateHash, order_id: orderId } });
      if (v?.payout && v.payout !== "Pending") return String(v.payout).toLowerCase();
    } catch { /* retry */ }
    await new Promise((res) => setTimeout(res, 2000));
  }
  return "unknown";
}

if (mode === "attack") {
  const fixtures = loadFixtures(resolve(ROOT, "fixtures/attacks/agent-demo"), { payee: st.payee, attacker: st.attacker, token: st.token, fakeToken: st.fakeToken });
  const rows = [];
  for (const f of fixtures as Fixture[]) {
    const orderId = hex32();
    const r = await purchase(orderFor(f, st.mandateHash, orderId));
    const ev = r.logs.filter((l) => l.startsWith("EVENT_JSON:")).map((l) => JSON.parse(l.slice(11))).find((e) => e.event === "receipt");
    const failing = ev ? ev.data[0].core.rules.filter((x: any) => !x.pass).map((x: any) => x.id) : [];
    const decision = (r.ret as any)?.decision ?? "error";
    // A release counts only once the payee was actually paid (audit M4-05).
    const payout = decision === "release" ? await payoutOf(r, (r.ret as any)?.order_id ?? orderId) : "none";
    const outcome = decision === "release" ? (payout === "done" ? "release" : `release, payout ${payout}`) : decision;
    const asExpected = r.ok && (r.ret as any)?.anchored === true && outcome === f.expected.decision && JSON.stringify(failing) === JSON.stringify(f.expected.failing);
    const knownMiss = f.label === "attack" && f.expected.decision === "release";
    rows.push({ id: f.id, label: f.label, knownMiss, decision: outcome, failing, coreHash: ev?.data[0].core_hash ?? null, tx: r.tx ? link(r.tx) : "", asExpected });
    console.log(`${asExpected ? "AS EXPECTED" : "UNEXPECTED "}  ${(knownMiss ? "miss" : f.label).padEnd(7)} ${f.id.padEnd(30)} ${outcome.padEnd(7)} ${failing.join(",").padEnd(6)} ${r.tx ? link(r.tx) : r.error}`);
  }
  const attacks = rows.filter((r) => r.label === "attack" && !r.knownMiss), misses = rows.filter((r) => r.knownMiss), controls = rows.filter((r) => r.label === "control");
  const summary = {
    attacks: attacks.length, attacksRefused: attacks.filter((r) => r.decision === "refuse" && r.coreHash).length,
    knownMisses: misses.length, knownMissesReleased: misses.filter((r) => r.decision === "release").length,
    controls: controls.length, controlsReleased: controls.filter((r) => r.decision === "release").length,
  };
  const falsePositives = summary.controls - summary.controlsReleased;
  console.log(`\nattacks refused ${summary.attacksRefused}/${summary.attacks} · known misses (inside the mandate) released ${summary.knownMissesReleased}/${summary.knownMisses} · controls paid ${summary.controlsReleased}/${summary.controls} · false positives ${falsePositives}`);
  writeFileSync(outPath("attack"), JSON.stringify({ date: new Date().toISOString(), gate: st.gate, agent: st.agent, mandateHash: st.mandateHash, summary: { ...summary, falsePositives }, rows }, null, 2) + "\n");
  process.exit(rows.every((r) => r.asExpected) ? 0 : 1);
}

if (mode === "direct") {
  // Every action except purchase must be refused by the protocol before it executes: no
  // transaction is included, and the error is the protocol's own (audit M4-04).
  const NOT_RECEIVER = /ReceiverMismatch|does not match transaction receiver/;
  const FULL_ACCESS = /RequiresFullAccess|requires full access/;
  const NO_DEPOSIT = /DepositWithFunctionCall|Deposit is not allowed with function call/;
  const steps: [string, RegExp | null, () => Promise<any>][] = [
    ["control: purchase a valid order (allowed)", null, () => agent.callFunctionRaw({ contractId: st.gate, methodName: "purchase", args: { order: orderFor({ id: "ctl-00-direct", label: "control", proposes: { item: "report-002", payee: st.payee, amount: "100000", asset: st.token }, expected: { decision: "release", failing: [] } }, st.mandateHash, hex32()) }, gas: 150n * 10n ** 12n })],
    ["token.ft_transfer to the agent, 1 yocto", new RegExp(`${NO_DEPOSIT.source}|${NOT_RECEIVER.source}`), () => agent.callFunctionRaw({ contractId: st.token, methodName: "ft_transfer", args: { receiver_id: st.agent, amount: "1" }, deposit: 1n })],
    ["token.ft_transfer without deposit", NOT_RECEIVER, () => agent.callFunctionRaw({ contractId: st.token, methodName: "ft_transfer", args: { receiver_id: st.agent, amount: "1" } })],
    ["token.ft_transfer_call to the gate", NOT_RECEIVER, () => agent.callFunctionRaw({ contractId: st.token, methodName: "ft_transfer_call", args: { receiver_id: st.gate, amount: "1", msg: "" } })],
    ["another gate method (refund)", /MethodNameMismatch|does not allow method/, () => agent.callFunctionRaw({ contractId: st.gate, methodName: "refund", args: { mandate_hash: st.mandateHash } })],
    ["another contract (the payee account)", NOT_RECEIVER, () => agent.callFunctionRaw({ contractId: st.payee, methodName: "anything", args: {} })],
    ["purchase with an attached deposit", NO_DEPOSIT, () => agent.callFunctionRaw({ contractId: st.gate, methodName: "purchase", args: { order: "x" }, deposit: 1n })],
    ["send NEAR", FULL_ACCESS, () => agent.transfer({ receiverId: st.attacker, amount: 1n } as any)],
    ["add a full-access key", FULL_ACCESS, () => agent.addFullAccessKey(KeyPair.fromRandom("ed25519").getPublicKey().toString())],
    ["delete the agent account", FULL_ACCESS, () => agent.deleteAccount(st.attacker)],
  ];
  const rows = [];
  for (const [name, reason, fn] of steps) {
    const r = await send(fn);
    const ok = reason === null ? r.ok && (r.ret as any)?.decision === "release" : !r.ok && !r.tx && reason.test(r.error);
    rows.push({ action: name, expected: reason === null ? "allowed, released" : `refused: ${reason.source}`, asExpected: ok, tx: r.tx ? link(r.tx) : "", detail: r.ok ? JSON.stringify(r.ret).slice(0, 160) : r.error.slice(0, 200) });
    console.log(`${ok ? "AS EXPECTED" : "UNEXPECTED "}  ${name}${r.tx ? "  " + link(r.tx) : ""}  (${(r.ok ? JSON.stringify(r.ret) : r.error).slice(0, 110)})`);
  }
  writeFileSync(outPath("direct"), JSON.stringify({ date: new Date().toISOString(), agent: st.agent, rows }, null, 2) + "\n");
  process.exit(rows.every((r) => r.asExpected) ? 0 : 1);
}

console.error("usage: run.ts attack | direct | probe --key <file>");
process.exit(2);
