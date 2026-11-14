// Receipt checker logic (M6). Runs in the browser with no wallet and no Sampan server:
// everything is recomputed from the receipt file and the NEAR RPC(s) the viewer chose.
// A check is "pass", "fail" (the receipt is wrong) or "unknown" (cannot verify, e.g. RPC
// errors or two RPCs disagree). The overall result is green only if every check passes.
import { parseEnvelope, MAX_EVENT_LOG, type Envelope } from "../../../packages/receipt/src/index.ts";
import { canonicalize, FormatError, hashHex, type Json } from "../../../packages/mandate/src/index.ts";
import { Rpc, RpcError, type Fetch } from "./rpc.ts";
import { KNOWN_GATES } from "./gates.ts";
import { base58 } from "@scure/base";

export type Status = "pass" | "fail" | "unknown";
export interface Check { id: string; title: string; status: Status; detail: string }
export interface Facts {
  decision: string; refusedBecause: string[]; network: string; gate: string; payee: string; item: string; amount: string; asset: string;
  buyer: string; agent: string | null; orderId: string; mandateHash: string; coreHash: string; agentNote: string | null;
}
export interface Result { overall: "verified" | "invalid" | "unverifiable"; checks: Check[]; facts: Facts | null }
export interface Options { rpcUrl: string; secondRpcUrl?: string; fetchFn: Fetch }


function overallOf(checks: Check[]): Result["overall"] {
  if (checks.some((c) => c.status === "fail")) return "invalid";
  if (checks.some((c) => c.status === "unknown")) return "unverifiable";
  return "verified";
}

/** NEP-413 buyer key as its NEAR implicit account (64 hex), for the transaction lookup. */
function implicitAccount(buyer: string): string | null {
  if (!buyer.startsWith("near:ed25519:")) return null;
  try {
    const key = base58.decode(buyer.slice(13)); // same decoder as the formats (M6-CR6)
    return key.length === 32 ? Array.from(key, (b) => b.toString(16).padStart(2, "0")).join("") : null;
  } catch {
    return null;
  }
}

/** Plain-language reason for each rule that can fail in an anchored receipt. */
const RULE_WORDS: Record<string, string> = {
  R3: "the buyer's mandate had already expired",
  R6: "the order asked to pay in a token the buyer did not approve",
  R7: "the amount was above the remaining budget or above the money held for this mandate",
  R8: "the order would have paid someone other than the payee the buyer signed",
  R9: "the item is not one the buyer approved",
};
/** The gate's receipt event for this order inside a transaction, if executed successfully. */
function findGateEvent(tx: any, gate: string, coreHash: string, orderId: string): { core: Json; blockHash: string } | null {
  for (const r of tx?.receipts_outcome ?? []) {
    const o = r?.outcome;
    if (o?.executor_id !== gate) continue; // a lookalike event from another contract never counts
    if (!o.status || "Failure" in o.status) continue; // nor an event from a failed receipt
    for (const log of o.logs ?? []) {
      if (typeof log !== "string" || !log.startsWith("EVENT_JSON:") || log.length > MAX_EVENT_LOG) continue;
      let ev: any;
      try { ev = JSON.parse(log.slice(11)); } catch { continue; }
      const d = ev?.standard === "sampan" && ev?.event === "receipt" ? ev?.data?.[0] : null;
      if (d && d.core_hash === coreHash && d.order_id === orderId) return { core: d.core, blockHash: String(r.block_hash) };
    }
  }
  return null;
}

interface ChainView { stored: any; tx: any; event: { core: Json; blockHash: string } | null; final: boolean; height: string | null; timestampNs: string | null; txFound: boolean }

async function readChain(rpc: Rpc, env: Envelope, senders: string[]): Promise<ChainView> {
  const gate = env.core.gate;
  const stored = await rpc.view(gate, "get_receipt", { mandate_hash: env.core.mandate_hash, order_id: env.order.order_id });
  const tx: any = await findTx(rpc, env.tx.decision, senders);
  const event = tx ? findGateEvent(tx, gate, env.coreHash, env.order.order_id) : null;
  const block = event ? await rpc.block(event.blockHash) : null;
  return { stored, tx, event, final: tx?.final_execution_status === "FINAL", height: block?.height ?? null, timestampNs: block?.timestampNs ?? null, txFound: Boolean(tx) };
}

export async function verifyReceipt(bytes: Uint8Array, opts: Options): Promise<Result> {
  const checks: Check[] = [];
  const add = (id: string, title: string, status: Status, detail: string) => checks.push({ id, title, status, detail });

  // 1. The file itself: format, fingerprints, the buyer's signature, order against mandate.
  let env: Envelope;
  try {
    env = parseEnvelope(bytes);
  } catch (e) {
    const msg = e instanceof FormatError ? `${e.code}: ${e.message}` : "the file could not be read";
    add("file", "The receipt file is complete and consistent", "fail", msg);
    return { overall: "invalid", checks, facts: null };
  }
  const m = env.signed.mandate;
  add("file", "The receipt file is complete and consistent", "pass", "Format, fingerprints and cross-references all match.");
  add("signature", "The buyer signed this mandate", "pass", `Valid ${env.signed.standard === "nep413" ? "NEAR (NEP-413)" : "Ethereum (ERC-191)"} signature by ${m.buyer}.`);
  const failed = env.core.rules.filter((r) => !r.pass).map((r) => r.id);
  const refusedBecause = failed.map((id) => RULE_WORDS[id] ?? `rule ${id} failed`);
  if (env.core.decision === "release") {
    add("order", "The order stays inside what the buyer signed", "pass", `Payee, item and token as signed; amount within the signed budget of ${m.max_amount} units.`);
  } else {
    // A refusal's order is outside the mandate by definition: say what was wrong (M6-CR3).
    add("order", "The refusal matches the buyer's limits", "pass", `The gate refused because ${refusedBecause.join("; ")}.`);
  }
  const facts: Facts = {
    decision: env.core.decision, refusedBecause, network: env.core.network, gate: env.core.gate, payee: env.order.payee, item: env.order.item,
    amount: env.order.amount, asset: env.order.asset, buyer: m.buyer, agent: m.agent, orderId: env.order.order_id,
    mandateHash: env.signed.mandateHash, coreHash: env.coreHash, agentNote: env.agentNote,
  };

  // 2. The chain, through the RPC(s) the viewer chose.
  let primary: Rpc, second: Rpc | null = null;
  try {
    primary = new Rpc(opts.rpcUrl, opts.fetchFn);
    if (opts.secondRpcUrl) second = new Rpc(opts.secondRpcUrl, opts.fetchFn);
  } catch (e) {
    add("rpc", "The NEAR RPC can be used", "unknown", (e as Error).message);
    return { overall: overallOf(checks), checks, facts };
  }
  // Sender hints for the RPC's `tx` lookup only; nothing is trusted from them (the checks read
  // the transaction itself). The testnet RPC ignores the hint, so a direct-checkout decision
  // sent by 1Click's account is found; **Assumption** for mainnet RPCs. An RPC that honoured the
  // hint would need 1Click's account, which the receipt does not name; the check then reads
  // "Cannot verify", never green (audit M7-09). The gate is one more harmless hint.
  const senders = [m.agent, m.refund_to, implicitAccount(m.buyer), m.gate].filter((x): x is string => Boolean(x));
  const first = await chainChecks(env, primary, senders);
  checks.push(...first);

  // Optional cross-check: the second RPC runs every chain check on its own and must give the
  // same answers, from a different host (M6-02).
  if (second) {
    const title = "A second RPC agrees";
    if (new URL(second.url).hostname === new URL(primary.url).hostname) {
      add("second-rpc", title, "unknown", "The second RPC is the same host as the first, so it is not an independent check.");
    } else {
      const other = await chainChecks(env, second, senders);
      const key = (cs: Check[]) => JSON.stringify(cs.map((c) => [c.id, c.status, c.detail]));
      const same = key(other) === key(first);
      add("second-rpc", title, same ? "pass" : "unknown", same ? `${new URL(second.url).hostname} gives the same answers for every check.` : `${new URL(second.url).hostname} gives different answers, so the result cannot be trusted.`);
    }
  }
  return { overall: overallOf(checks), checks, facts };
}

const TX_CHANGES_CODE_OR_KEYS = ["DeployContract", "DeployGlobalContract", "UseGlobalContract", "AddKey", "DeleteKey", "DeleteAccount"];

/** Every check that needs the chain, through one RPC. Never throws: unusable answers become
 *  "Cannot verify" (M6-CR2). Details are capped so RPC-supplied text stays short (M6-10). */
async function chainChecks(env: Envelope, rpc: Rpc, senders: string[]): Promise<Check[]> {
  const out: Check[] = [];
  const add = (id: string, title: string, status: Status, detail: string) => out.push({ id, title, status, detail: detail.length > 300 ? detail.slice(0, 297) + "..." : detail });
  try {
    await chainChecksInner(env, rpc, senders, add);
  } catch (e) {
    add("rpc", "The NEAR RPC answered usably", "unknown", e instanceof RpcError ? e.message : "The RPC returned data the checker could not use.");
  }
  return out;
}

async function chainChecksInner(env: Envelope, rpc: Rpc, senders: string[], add: (id: string, title: string, status: Status, detail: string) => void): Promise<void> {
  const m = env.signed.mandate;
  const gate = env.core.gate;
  const chain = await rpc.chainId();
  if (chain !== env.core.network) {
    add("network", `The RPC is on ${env.core.network}`, "unknown", `The RPC reports network "${chain}", so this ${env.core.network} receipt cannot be checked with it.`);
    return;
  }
  // The gate must be a known deployment running a reviewed build (M6-CR1).
  const list = KNOWN_GATES[env.core.network];
  if (list.length === 0) {
    add("gate", "The gate is a known Sampan gate", "unknown", `This checker version lists no reviewed gate on ${env.core.network} yet (M6-12).`);
    return;
  }
  const known = list.find((g) => g.account === gate);
  if (!known) {
    add("gate", "The gate is a known Sampan gate", "fail", `${gate} is not a known gate on ${env.core.network}. Anyone can deploy a look-alike contract.`);
    return;
  }
  const code = await rpc.codeHash(gate);
  const config = await rpc.view(gate, "get_config", {});
  if (!known.codeHashes.includes(code)) add("gate", "The gate is a known Sampan gate", "fail", `${gate} runs code ${code}, not a reviewed build.`);
  else if (config?.token !== known.token || env.core.observed.asset !== known.token) add("gate", "The gate is a known Sampan gate", "fail", "The gate's settlement token is not the expected one.");
  else add("gate", "The gate is a known Sampan gate", "pass", `${known.label}: reviewed contract build ${code.slice(0, 8)}..., token ${known.token}.`);

  // Whoever holds a full-access key on the gate can deploy other code, write a record, emit
  // an event and deploy the reviewed build back. Only a locked gate can be trusted (M6-01).
  const keys = await rpc.accessKeys(gate);
  if (keys.some((k) => k === "FullAccess")) add("locked", "Nobody can change the gate", "unknown", `${gate} still has an owner key, so its records could have been written by other code. This is expected for the test gate (decision Q16); the mainnet gate is locked.`);
  else add("locked", "Nobody can change the gate", "pass", "The gate account has no owner key: its code cannot be replaced.");

  const view = await readChain(rpc, env, senders);

  // The gate's stored anchor.
  if (!view.stored) add("anchor", "The gate recorded this decision", "fail", "The gate has no receipt for this mandate and order.");
  else if (view.stored.core_hash !== env.coreHash) add("anchor", "The gate recorded this decision", "fail", "The gate recorded a different receipt for this order.");
  else if (view.stored.decision !== env.core.decision) add("anchor", "The gate recorded this decision", "fail", `The gate recorded "${view.stored.decision}", the file says "${env.core.decision}".`);
  else add("anchor", "The gate recorded this decision", "pass", `Stored on ${gate}, decision "${env.core.decision}".`);

  // The decision transaction: final, executed by the gate, carrying this exact receipt, and
  // not a transaction that changed the gate's code or keys around it (M6-01).
  const t = view.tx?.transaction;
  const changesGate = t && (t.signer_id === gate || (Array.isArray(t.actions) && t.actions.some((a: any) => a && typeof a === "object" && TX_CHANGES_CODE_OR_KEYS.some((k) => k in a))));
  if (!view.txFound) add("tx", "The decision transaction is on chain and final", "unknown", "The RPC could not find the decision transaction (it was looked up with the buyer, agent, refund account and gate as sender hints).");
  else if (changesGate) add("tx", "The decision transaction is on chain and final", "fail", "The decision transaction was sent by the gate itself or changed code or keys: it cannot prove a decision of the reviewed contract.");
  else if (!view.event) add("tx", "The decision transaction is on chain and final", "fail", "The transaction does not contain this receipt from the gate (wrong transaction, another contract, or a failed step).");
  else if (!view.final) add("tx", "The decision transaction is on chain and final", "unknown", "The transaction is not final yet.");
  else if (canonicalize(view.event.core) !== canonicalize(env.core as unknown as Json)) add("tx", "The decision transaction is on chain and final", "fail", "The receipt in the transaction differs from the file.");
  else add("tx", "The decision transaction is on chain and final", "pass", "Final, executed by the gate, with this exact receipt.");

  // The gate's code and keys in the decision block itself, where the RPC keeps that history
  // (archival RPCs do; regular ones keep about two days) (M6-01).
  if (view.event) {
    const then = await rpc.historicGate(gate, view.event.blockHash);
    const title = "The gate ran reviewed code when it decided";
    if (then) {
      if (!known.codeHashes.includes(then.codeHash)) add("then", title, "fail", `In the decision block the gate ran code ${then.codeHash}, not a reviewed build.`);
      else if (then.keys.includes("FullAccess")) add("then", title, "unknown", "Reviewed code, but the gate still had an owner key in that block.");
      else add("then", title, "pass", "Reviewed code and no owner key in the decision block.");
    } else if (known.lockedAtBlock !== undefined && view.height !== null && BigInt(view.height) > BigInt(known.lockedAtBlock) && !keys.includes("FullAccess") && keys.length === 0) {
      // No history for that block, but it comes after the recorded lock: with no keys since, the
      // code cannot have changed, so it is the reviewed code checked above (A2-01).
      add("then", title, "pass", `Decided at block ${view.height}, strictly after the gate was locked at block ${known.lockedAtBlock}; nobody could change its code since.`);
    } else {
      // Never drop this check: without history or a recorded lock, a decision made while the gate
      // still had an owner key cannot be told apart (A2-01).
      add("then", title, "unknown", "This RPC has no history for the decision block. Choose an archival RPC (archival-rpc.*.near.org) to check it.");
    }
  }

  // Block height and expiry (R3) from the block that holds the gate's step.
  if (view.height === null) add("block", "The block height matches", "unknown", "No block to compare with.");
  else if (view.height !== env.core.block_height) add("block", "The block height matches", "fail", `The gate decided in block ${view.height}, the file says ${env.core.block_height}.`);
  else add("block", "The block height matches", "pass", `Block ${view.height}.`);
  if (view.timestampNs !== null && env.core.decision === "release") {
    const inTime = BigInt(view.timestampNs) < BigInt(m.expiry_ns);
    add("expiry", "The mandate had not expired", inTime ? "pass" : "fail", inTime ? "Decided before the mandate's expiry." : "Released after the mandate expired.");
  }

  // Payment: a release must have reached the payee; a refusal must not have paid anyone.
  if (view.stored && view.stored.core_hash === env.coreHash) {
    const payout = String(view.stored.payout);
    if (env.core.decision === "release") {
      add("payout", "The payee was paid", payout === "Done" ? "pass" : payout === "Pending" ? "unknown" : "fail",
        payout === "Done" ? `${env.order.amount} units of ${env.order.asset} went to ${env.order.payee}.` : `Payout status: ${payout}.`);
    } else {
      add("payout", "No money moved for this refusal", payout === "None" ? "pass" : "fail", payout === "None" ? "The gate made no payment." : `Unexpected payout status: ${payout}.`);
    }
  }

  // The other transaction hashes the receipt lists must be what they claim (M6-06).
  if (env.tx.payout) {
    const ptx = env.tx.payout === env.tx.decision ? view.tx : await findTx(rpc, env.tx.payout, senders);
    const ev = ptx ? gateEvent(ptx, gate, (d) => d.order_id === env.order.order_id && d.mandate_hash === env.core.mandate_hash, "payout") : null;
    if (!ptx) add("payout-tx", "The payout transaction in the receipt is on chain", "unknown", "The RPC could not find the payout transaction listed in the receipt.");
    else if (ptx.final_execution_status !== "FINAL") add("payout-tx", "The payout transaction in the receipt is on chain", "unknown", "The payout transaction is not final yet.");
    else if (!ev || ev.data.status !== "done") add("payout-tx", "The payout transaction in the receipt is on chain", "fail", "The listed payout transaction does not contain the gate's completed payout for this order.");
    else add("payout-tx", "The payout transaction in the receipt is on chain", "pass", "It contains the gate's completed payout for this order.");
  }
  if (env.tx.deposit) {
    const dtx = await findTx(rpc, env.tx.deposit, senders);
    const ev = dtx ? gateEvent(dtx, gate, (d) => d.mandate_hash === env.core.mandate_hash, "funded") : null;
    if (!dtx) add("deposit-tx", "The deposit transaction in the receipt is on chain", "unknown", "The RPC could not find the deposit transaction listed in the receipt.");
    else if (dtx.final_execution_status !== "FINAL") add("deposit-tx", "The deposit transaction in the receipt is on chain", "unknown", "The deposit transaction is not final yet.");
    else if (!ev) add("deposit-tx", "The deposit transaction in the receipt is on chain", "fail", "The listed deposit transaction did not fund this mandate at the gate.");
    else add("deposit-tx", "The deposit transaction in the receipt is on chain", "pass", "It funded this mandate at the gate.");
  }
}

async function findTx(rpc: Rpc, hash: string, senders: string[]): Promise<any | null> {
  for (const s of senders) {
    const tx = await rpc.tx(hash, s);
    if (tx) return tx;
  }
  return null;
}

/** A sampan event of the given kind emitted by the gate in a successful receipt of `tx`. */
function gateEvent(tx: any, gate: string, match: (d: any) => boolean, kind: string): { data: any; blockHash: string } | null {
  for (const r of tx?.receipts_outcome ?? []) {
    const o = r?.outcome;
    if (o?.executor_id !== gate || !o.status || "Failure" in o.status) continue;
    for (const log of o.logs ?? []) {
      if (typeof log !== "string" || !log.startsWith("EVENT_JSON:") || log.length > MAX_EVENT_LOG) continue;
      let ev: any;
      try { ev = JSON.parse(log.slice(11)); } catch { continue; }
      const d = ev?.standard === "sampan" && ev?.event === kind ? ev?.data?.[0] : null;
      if (d && match(d)) return { data: d, blockHash: String(r.block_hash) };
    }
  }
  return null;
}

/** Receipt bytes from a link fragment `#r=<base64url>` (no request is made for a link). */
export function receiptFromFragment(hash: string): Uint8Array | null {
  const m = /^#r=([A-Za-z0-9_-]{1,30000})$/.exec(hash);
  if (!m) return null;
  const b64 = m[1].replace(/-/g, "+").replace(/_/g, "/");
  try {
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

export { hashHex };
