#!/usr/bin/env node
// Mainnet gate deploy (audit A1C-06). FOR A PERSON TO RUN. Claude Code sessions and CI never
// run this file: it stops unless it has an interactive terminal, and it never reads a key
// from the environment or a file.
//
//   make wasm-release
//   node scripts/mainnet/deploy-gate.mjs plan   --gate <gate>.near --guardian <guardian>.near --code-hash <hash>
//   node scripts/mainnet/deploy-gate.mjs deploy --gate <gate>.near --guardian <guardian>.near --code-hash <hash>
//   (smoke test with the smallest amounts: scripts/mainnet-proof, M5, also person-run)
//   node scripts/mainnet/deploy-gate.mjs lock   --gate <gate>.near --code-hash <hash>
//
// `plan` only reads. `deploy` sends ONE transaction (DeployContract + new(config)) signed by
// the gate account, then one storage_deposit with USDC. `lock` deletes every access key of
// the gate in ONE transaction and re-reads the key list at final. Every step stops on the
// first failure. `--code-hash` is the hash recorded in the reviewed PR for the audited
// commit, typed by the person; the build must match it.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { args, stop, ask, requirePerson } from "./cli.mjs";

export const MAINNET_RPC = "https://rpc.mainnet.near.org";
export const USDC = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";
export const EMPTY_CODE_HASH = "11111111111111111111111111111111";
/** The gate build audited in A1R and signed off on 7 Nov 2026 (`make wasm-release`). A new build needs a new review. */
export const REVIEWED_CODE_HASH = "2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA";
const HOUR_NS = 3_600_000_000_000n;
const BYTE_COST = 10n ** 19n;

/** The reviewed mainnet config (docs/audits/A1-contract.md, "Mainnet readiness"). */
/** 0.00125 NEAR: USDC's storage minimum as reviewed (A1-contract, "Mainnet readiness"). */
export const REVIEWED_REGISTRATION_DEPOSIT = "1250000000000000000000";

export function mainnetConfig({ guardian, registrationDeposit = REVIEWED_REGISTRATION_DEPOSIT }) {
  return {
    network: "mainnet", token: USDC, min_funding: "1000000", max_escrow_per_mandate: "10000000",
    max_total_escrow: "50000000", max_mandates: 100, max_orders_per_mandate: 16, // max_mandates: lead decision A1R-03, 7 Nov 2026
    registration_deposit: registrationDeposit, max_lifetime_ns: Number(24n * HOUR_NS), guardian,
  };
}

const NAMED_MAINNET = /^(?=.{2,64}$)([a-z\d]+[-_])*[a-z\d]+(\.([a-z\d]+[-_])*[a-z\d]+)*\.near$/;

/** Checks that need no network. Returns a list of problems (empty: fine). */
export function checkInputs({ gate, guardian, codeHash, wasmHash, config }) {
  const p = [];
  if (!NAMED_MAINNET.test(gate ?? "")) p.push("gate must be a named .near account");
  if (guardian !== undefined) {
    if (!NAMED_MAINNET.test(guardian ?? "")) p.push("guardian must be a named .near account");
    if (guardian === gate) p.push("guardian must not be the gate account");
  }
  if (!/^[1-9A-HJ-NP-Za-km-z]{43,44}$/.test(codeHash ?? "")) p.push("--code-hash must be the base58 hash from the reviewed PR");
  if (wasmHash !== undefined && wasmHash !== codeHash) p.push(`the local build ${wasmHash} is not the reviewed code ${codeHash}`);
  if (config) {
    if (config.network !== "mainnet") p.push("config network must be mainnet");
    if (config.token !== USDC) p.push("config token must be native USDC");
    if (config.max_lifetime_ns !== Number(24n * HOUR_NS)) p.push("config lifetime must be 24 hours");
  }
  return p;
}

/** Checks on what the chain returned before deploying. */
export function checkChain({ chainId, account, stateKeys, metadata, bounds, config, balance }) {
  const p = [];
  if (chainId !== "mainnet") p.push(`RPC chain is ${chainId}, not mainnet`);
  if (!account) p.push("gate account does not exist");
  else if (account.code_hash !== EMPTY_CODE_HASH) p.push("gate account already has a contract");
  if (stateKeys !== 0) p.push("gate account has state");
  if (metadata?.symbol !== "USDC" || metadata?.decimals !== 6) p.push("token metadata is not USDC with 6 decimals");
  if (!bounds || BigInt(config.registration_deposit) < BigInt(bounds.min)) p.push("registration_deposit is below USDC's storage minimum");
  if (bounds && BigInt(config.registration_deposit) > BigInt(bounds.min)) p.push("registration_deposit is above USDC's storage minimum");
  // A1R-06: the value is fixed in the reviewed config, never taken from the chain.
  if (bounds && bounds.min !== REVIEWED_REGISTRATION_DEPOSIT) p.push("USDC's storage minimum is not the reviewed 0.00125 NEAR; stop and review the config");
  // Code (about 3.2 NEAR) plus one registration with USDC and 1 NEAR headroom; mandates pay
  // their own storage since A1 (register_mandate deposit).
  const need = 5n * 10n ** 24n;
  if (balance !== undefined && BigInt(balance) < need) p.push("gate balance is below 5 NEAR");
  return p;
}

/** Checks after deploy: config, code, totals. */
export function checkDeployed({ config, expectedConfig, codeHash, expectedHash, totals }) {
  const p = [];
  const norm = (o) => JSON.stringify(Object.keys(o ?? {}).sort().map((k) => [k, String(o[k])]));
  if (norm(config) !== norm(expectedConfig)) p.push("get_config differs from the intended config");
  if (codeHash !== expectedHash) p.push("deployed code hash differs from the reviewed hash");
  if (!totals || totals.total_escrow !== "0" || totals.total_refund_due !== "0" || totals.mandates !== 0 || totals.stopped !== false) p.push("gate totals are not zero");
  return p;
}

/** A locked gate has no access keys at all. */
export function checkLocked(keys) {
  return keys.length === 0 ? [] : [`gate still has ${keys.length} access key(s)`];
}

export const reservationPerMandate = (orders, registrationDeposit) =>
  (2400n + BigInt(orders) * 450n) * BYTE_COST + 2n * BigInt(registrationDeposit);

// ---- person-run flow ------------------------------------------------------------------------

async function main() {
  const a = args(process.argv.slice(2));
  if (!["plan", "deploy", "lock", "verify"].includes(a.cmd)) stop(["usage: plan|deploy|lock|verify --gate <gate>.near [--guardian <account>.near] --code-hash <hash>"]);
  requirePerson();

  const { Account, JsonRpcProvider, KeyPair, PublicKey, actions } = await import("near-api-js");
  const provider = new JsonRpcProvider({ url: MAINNET_RPC });
  const view = (contractId, method, x = {}) => provider.callFunction({ contractId, method, args: x , blockQuery: { finality: "final" } });
  const wasm = readFileSync(resolve(import.meta.dirname, "../../target/wasm32-unknown-unknown/release/sampan_gate.wasm"));
  const { base58 } = await import("@scure/base");
  const wasmHash = base58.encode(createHash("sha256").update(wasm).digest());
  const chainId = (await provider.viewNodeStatus()).chain_id;
  if (chainId !== "mainnet") stop([`RPC chain is ${chainId}, not mainnet`]);

  // verify: read-only checks after a deploy or lock signed with a hardware wallet (A1R-10b):
  // config, code, totals, USDC registration, and whether any key is left.
  if (a.cmd === "verify") {
    stop(checkInputs({ gate: a.gate, guardian: a.guardian, codeHash: a["code-hash"] }));
    const bounds = await view(USDC, "storage_balance_bounds");
    const expected = mainnetConfig({ guardian: a.guardian });
    const deployed = await provider.viewAccount({ accountId: a.gate, blockQuery: { finality: "final" } });
    const problems = checkDeployed({ config: await view(a.gate, "get_config"), expectedConfig: expected, codeHash: deployed.code_hash, expectedHash: a["code-hash"], totals: await view(a.gate, "get_totals") });
    if (bounds?.min !== REVIEWED_REGISTRATION_DEPOSIT) problems.push("USDC's storage minimum is not the reviewed 0.00125 NEAR");
    const reg = await view(USDC, "storage_balance_of", { account_id: a.gate });
    if (!reg) problems.push("the gate is not registered with USDC");
    const keys = (await provider.viewAccessKeyList({ accountId: a.gate, finalityQuery: { finality: "final" } })).keys;
    console.log(`code ${deployed.code_hash}; balance ${deployed.amount} yoctoNEAR; USDC registration ${reg ? "yes" : "no"}; access keys left: ${keys.length}`);
    stop(problems);
    // The record the proof scripts read (M8-11): written here too, so the hardware-wallet path has it.
    mkdirSync(resolve(import.meta.dirname, "../../examples"), { recursive: true });
    const rec = resolve(import.meta.dirname, "../../examples/mainnet-gate.json");
    let prev = {};
    try { prev = JSON.parse(readFileSync(rec, "utf8")); } catch { /* first write */ }
    // --lock-tx: the transaction that deleted the keys, recorded for the checker's lock height (A2-01).
    if (a["lock-tx"] !== undefined && !/^[1-9A-HJ-NP-Za-km-z]{43,44}$/.test(a["lock-tx"])) stop(["--lock-tx must be a transaction hash"]);
    const lock = a["lock-tx"] ? { lock_tx: a["lock-tx"] } : {};
    writeFileSync(rec, JSON.stringify({ ...prev, ...lock, gate: a.gate, code_hash: deployed.code_hash, guardian: a.guardian, locked: keys.length === 0, verified_at: new Date().toISOString() }, null, 2) + "\n");
    console.log(keys.length === 0 ? "Verified: reviewed code, intended config, registered with USDC, and locked (no keys)." : "Verified: reviewed code, intended config, registered with USDC. NOT locked yet: delete every key, then run verify again.");
    return;
  }

  if (a.cmd === "lock") {
    stop(checkInputs({ gate: a.gate, codeHash: a["code-hash"] }));
    const acc = await provider.viewAccount({ accountId: a.gate, blockQuery: { finality: "final" } });
    stop(acc.code_hash === a["code-hash"] ? [] : ["deployed code is not the reviewed code"]);
    const keys = (await provider.viewAccessKeyList({ accountId: a.gate, finalityQuery: { finality: "final" } })).keys;
    console.log(`The gate has ${keys.length} access key(s). Locking deletes all of them for good: nobody can change the gate again.`);
    if ((await ask(`Type "lock ${a.gate}" to continue: `)) !== `lock ${a.gate}`) stop(["not confirmed"]);
    const key = await ask("Gate full-access secret key (input hidden; prefer a hardware wallet signer): ", { hidden: true });
    const gate = new Account(a.gate, provider, KeyPair.fromString(key).toString());
    const r = await gate.signAndSendTransaction({ receiverId: a.gate, actions: keys.map((k) => actions.deleteKey(PublicKey.fromString(k.public_key))) });
    const after = (await provider.viewAccessKeyList({ accountId: a.gate, finalityQuery: { finality: "final" } })).keys;
    stop(checkLocked(after));
    mkdirSync(resolve(import.meta.dirname, "../../examples"), { recursive: true });
    const out = resolve(import.meta.dirname, "../../examples/mainnet-gate.json");
    let prev = {};
    try { prev = JSON.parse(readFileSync(out, "utf8")); } catch { /* first write */ }
    writeFileSync(out, JSON.stringify({ ...prev, gate: a.gate, code_hash: acc.code_hash, lock_tx: r.transaction.hash }, null, 2) + "\n");
    console.log(`Locked. Lock transaction ${r.transaction.hash}; written to examples/mainnet-gate.json.`);
    return;
  }

  const metadata = await view(USDC, "ft_metadata");
  const bounds = await view(USDC, "storage_balance_bounds");
  const config = mainnetConfig({ guardian: a.guardian });
  stop(checkInputs({ gate: a.gate, guardian: a.guardian, codeHash: a["code-hash"], wasmHash, config }));
  const account = await provider.viewAccount({ accountId: a.gate, blockQuery: { finality: "final" } }).catch(() => null);
  // A1R-10: a failed read is a stop, never "no state".
  const state = await provider.query({ request_type: "view_state", finality: "final", account_id: a.gate, prefix_base64: "" }).catch(() => stop(["could not read the gate's state; stop"]));
  await provider.viewAccount({ accountId: a.guardian, blockQuery: { finality: "final" } }).catch(() => stop(["guardian account does not exist"]));
  stop(checkChain({ chainId, account, stateKeys: state.values.length, metadata, bounds, config, balance: account?.amount }));
  console.log("Plan (all checks passed):");
  console.log(JSON.stringify({ gate: a.gate, code_hash: wasmHash, config, deposit_per_mandate_yocto: String(reservationPerMandate(16, config.registration_deposit)) }, null, 2));
  if (a.cmd === "plan") {
    // For signing with a hardware wallet instead of the typed key (A1R-10b): one transaction
    // with DeployContract + FunctionCall new(config), then `verify`.
    console.log("\nTo sign with a hardware wallet: send ONE transaction from the gate account with");
    console.log("  1. DeployContract: target/wasm32-unknown-unknown/release/sampan_gate.wasm");
    console.log(`  2. FunctionCall new, 30 Tgas, no deposit, args: ${JSON.stringify({ config })}`);
    // The same transaction as one near-cli-rs command (syntax from its guide; `sign-with-ledger` is
    // an Assumption: check the CLI's summary before you confirm).
    console.log("\nOr with near-cli-rs, as ONE command (single quotes keep the JSON intact):");
    console.log(`near contract deploy ${a.gate} use-file target/wasm32-unknown-unknown/release/sampan_gate.wasm with-init-call new json-args '${JSON.stringify({ config })}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' network-config mainnet sign-with-ledger send`);
    console.log(`Then: node scripts/mainnet/deploy-gate.mjs verify --gate ${a.gate} --guardian ${a.guardian} --code-hash ${a["code-hash"]}`);
    return;
  }

  if ((await ask(`Type "deploy ${a.gate}" to send ONE transaction (deploy + init): `)) !== `deploy ${a.gate}`) stop(["not confirmed"]);
  const key = await ask("Gate full-access secret key (input hidden; prefer a hardware wallet signer): ", { hidden: true });
  const gate = new Account(a.gate, provider, KeyPair.fromString(key).toString());
  const r = await gate.signAndSendTransaction({
    receiverId: a.gate,
    actions: [actions.deployContract(wasm), actions.functionCall("new", { config }, 30n * 10n ** 12n, 0n)],
  });
  if (r.status?.Failure) stop([`deploy transaction failed: ${JSON.stringify(r.status.Failure).slice(0, 200)}`]);
  const deployed = await provider.viewAccount({ accountId: a.gate, blockQuery: { finality: "final" } });
  stop(checkDeployed({ config: await view(a.gate, "get_config"), expectedConfig: config, codeHash: deployed.code_hash, expectedHash: a["code-hash"], totals: await view(a.gate, "get_totals") }));
  if (!(await view(USDC, "storage_balance_of", { account_id: a.gate }))) {
    const s = await gate.callFunctionRaw({ contractId: USDC, methodName: "storage_deposit", args: { account_id: a.gate, registration_only: true }, deposit: BigInt(bounds.min), gas: 30n * 10n ** 12n });
    if (s.status?.Failure) stop(["registering the gate with USDC failed"]);
  }
  stop((await view(USDC, "storage_balance_of", { account_id: a.gate })) ? [] : ["gate is not registered with USDC"]);
  mkdirSync(resolve(import.meta.dirname, "../../examples"), { recursive: true });
  writeFileSync(resolve(import.meta.dirname, "../../examples/mainnet-gate.json"), JSON.stringify({ gate: a.gate, code_hash: deployed.code_hash, deploy_tx: r.transaction.hash, config }, null, 2) + "\n");
  console.log(`Deployed and initialised in ${r.transaction.hash}. Next: the smallest-amount smoke test, then "lock".`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((e) => { console.error("error: " + String(e?.message ?? e).replace(/[1-9A-HJ-NP-Za-km-z]{80,}/g, "[redacted]")); process.exit(1); });
}
