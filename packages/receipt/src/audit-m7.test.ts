// Independent audit M7 (docs/audits/M7.md): exploit tests for the receipt packer.
// Each "M7-NN ..." test asserts the REQUIRED behaviour, so it FAILS while its finding is
// open. "control: ..." tests pass today and must keep passing. Synthetic transactions shaped
// like NEAR RPC answers (EXPERIMENTAL_tx_status), built from the shared vectors. No network.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { canonicalize, hashHex } from "@sampan/mandate";
import { base58 } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { packReceipt, PackError, type TxFetch } from "./pack.ts";

const DIR = resolve(import.meta.dirname, "../../../fixtures/vectors");
const vecText = (rel: string) => Buffer.from(JSON.parse(readFileSync(join(DIR, rel), "utf8")).input_b64, "base64").toString("utf8");
const signedText = vecText("signed_mandate/nep413-valid.json");
const otherSignedText = vecText("signed_mandate/erc191-valid-v01.json");
const orderText = vecText("order/valid.json");
const core = JSON.parse(vecText("receipt_core/release.json"));
const coreHash = hashHex(canonicalize(core));
const orderId = JSON.parse(orderText).order_id;
// The gate named in the vectors' core and mandate: here the packer's `gate` input matches it.
const GATE = core.gate as string;
const TOKEN = core.observed.asset as string;
const h58 = (l: string) => base58.encode(sha256(new TextEncoder().encode(l)));
const D = h58("decision"), M = h58("mandate"), DEP = h58("deposit");
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64");
const ev = (event: string, data: object) => `EVENT_JSON:${JSON.stringify({ standard: "sampan", version: "1.0.0", event, data: [data] })}`;
const outcome = (executor: string, logs: string[], status: any = { SuccessValue: "" }) => ({ outcome: { executor_id: executor, status, logs } });
const receiptOut = (c = core, h = coreHash, id = orderId, executor = GATE) => outcome(executor, [ev("receipt", { core: c, core_hash: h, order_id: id })]);
const payoutOut = (mandateHash = core.mandate_hash, status = "done") => outcome(GATE, [ev("payout", { mandate_hash: mandateHash, order_id: orderId, status })]);
const fc = (method: string, args: unknown) => ({ FunctionCall: { method_name: method, args: b64(args) } });
const purchaseTx = (outcomes: any[] = [receiptOut(), payoutOut()], extra: object = {}) => ({
  final_execution_status: "FINAL", status: { SuccessValue: "" },
  transaction: { receiver_id: GATE, actions: [fc("purchase", { order: orderText })], ...extra }, receipts_outcome: outcomes,
});
const registerTx = (actions = [fc("register_mandate", { signed_mandate: signedText })]) => ({
  final_execution_status: "FINAL", status: { SuccessValue: "" }, transaction: { receiver_id: GATE, actions }, receipts_outcome: [],
});
const fundedTx = (mandateHash = core.mandate_hash) => ({
  final_execution_status: "FINAL", status: { SuccessValue: "" },
  transaction: { receiver_id: TOKEN, actions: [fc("ft_transfer_call", { receiver_id: GATE, amount: "1", msg: JSON.stringify({ mandate_hash: mandateHash }) })] },
  receipts_outcome: [outcome(GATE, [ev("funded", { mandate_hash: mandateHash, amount: "1", escrow: "1", refund_due: "0" })])],
});
const fetcher = (txs: Record<string, any>): TxFetch => async (h) => txs[h] ?? null;
const input = { gate: GATE, token: TOKEN, decisionTx: D, mandateTx: M };
const code = async (txs: Record<string, any>, extra: object = {}) => {
  try {
    await packReceipt({ ...input, ...extra } as any, fetcher(txs));
    return "ok";
  } catch (e) {
    return e instanceof PackError ? e.code : `other:${(e as Error).message}`;
  }
};

describe("controls (pass today and must keep passing)", () => {
  it("control: packs a release whose gate input matches the core's gate", async () => {
    expect(await code({ [D]: purchaseTx(), [M]: registerTx() })).toBe("ok");
  });
  it("control: a deposit transaction that funded this mandate is accepted", async () => {
    expect(await code({ [D]: purchaseTx(), [M]: registerTx(), [DEP]: fundedTx() }, { depositTx: DEP })).toBe("ok");
  });
});

// ---- M7-01 (Medium): the deposit transaction is copied into the envelope unread ----------
describe("M7-01 the packer must read and check the deposit transaction", () => {
  it("M7-01 a deposit transaction that cannot be found is refused", async () => {
    const c = await code({ [D]: purchaseTx(), [M]: registerTx() }, { depositTx: DEP });
    expect(c).not.toBe("ok");
    expect(c.startsWith("other:")).toBe(false);
  });
  it("M7-01 a deposit transaction that did not fund this mandate is refused", async () => {
    // The live equivalent: examples/testnet/agent-release.json with tx.deposit set to the
    // refusal's decision transaction checks red ("deposit-tx: fail") in the checker.
    expect(await code({ [D]: purchaseTx(), [M]: registerTx(), [DEP]: fundedTx("ab".repeat(32)) }, { depositTx: DEP })).not.toBe("ok");
    expect(await code({ [D]: purchaseTx(), [M]: registerTx(), [DEP]: purchaseTx() }, { depositTx: DEP })).not.toBe("ok");
  });
});

// ---- M7-02 (Low): the decision hash written is not tied to the transaction read ----------
describe("M7-02 the fetched decision transaction must be the one asked for", () => {
  it("M7-02 a fetched transaction whose own hash differs from decisionTx is refused", async () => {
    expect(await code({ [D]: purchaseTx(undefined, { hash: h58("another transaction") }), [M]: registerTx() })).not.toBe("ok");
  });
});

// ---- M7-03 (Low): the `gate` input is not bound to the gate the receipt names ------------
describe("M7-03 the packer must only accept events executed by the gate the core names", () => {
  it("M7-03 a lookalike contract's event naming the real gate in its core is refused", async () => {
    const EVIL = "evil.testnet";
    const tx = purchaseTx([receiptOut(core, coreHash, orderId, EVIL)]);
    expect(await code({ [D]: tx, [M]: registerTx() }, { gate: EVIL })).not.toBe("ok");
  });
});

// ---- M7-04 (Low): first order-shaped / mandate-shaped call wins -------------------------
describe("M7-04 the packer must use the order and mandate that match the receipt, not the first found", () => {
  const delivery = (first: any) => ({
    final_execution_status: "FINAL", status: { SuccessValue: "" },
    transaction: { receiver_id: "intents.testnet", actions: [first] },
    receipts: [{ receiver_id: TOKEN, receipt: { Action: { actions: [fc("ft_transfer_call", { receiver_id: GATE, amount: "1", msg: JSON.stringify({ mandate_hash: core.mandate_hash, order: orderText }) })] } } }],
    receipts_outcome: [receiptOut()],
  });
  it("M7-04 an unrelated earlier call named purchase with junk text does not crash or hide the order", async () => {
    expect(await code({ [D]: delivery(fc("purchase", { order: "not an order" })), [M]: registerTx() })).toBe("ok");
  });
  it("M7-04 an earlier call carrying another valid order does not hide the order", async () => {
    const other = canonicalize({ ...JSON.parse(orderText), order_id: "ee".repeat(32) });
    expect(await code({ [D]: delivery(fc("purchase", { order: other })), [M]: registerTx() })).toBe("ok");
  });
  it("M7-04 a mandate transaction carrying another signed mandate first still yields this mandate", async () => {
    const two = registerTx([fc("register_mandate", { signed_mandate: otherSignedText }), fc("register_mandate", { signed_mandate: signedText })]);
    expect(await code({ [D]: purchaseTx(), [M]: two })).toBe("ok");
  });
});

// ---- M7-05 (Low): two gate decisions in one transaction cannot be packed ----------------
describe("M7-05 a transaction with two gate decisions can still be packed for each order", () => {
  it("M7-05 the receipt for a chosen order is packed when another order was decided in the same transaction", async () => {
    // e.g. an agent's function-call key batching two purchase actions, or two deliveries in
    // one batched intents transaction. The checker handles this (it matches order_id); the
    // packer refuses both. `orderId` is a suggested selector; the fix may name it otherwise.
    const core2 = { ...core, order_hash: "ab".repeat(32) };
    const tx = purchaseTx([receiptOut(), receiptOut(core2, hashHex(canonicalize(core2)), "cd".repeat(32))]);
    expect(await code({ [D]: tx, [M]: registerTx() }, { orderId })).toBe("ok");
  });
});

// ---- M7-06 (Info): payout event not matched on mandate_hash -----------------------------
describe("M7-06 the payout transaction must hold this mandate's completed payout", () => {
  it("M7-06 a completed payout for the same order_id under another mandate is not recorded", async () => {
    const env = await packReceipt(input, fetcher({ [D]: purchaseTx([receiptOut(), payoutOut("ff".repeat(32))]), [M]: registerTx() }));
    expect(env.tx.payout).toBeNull();
  });
});

// ---- M7-07 (Info): a string status throws a TypeError instead of a PackError ------------
describe("M7-07 unusual RPC status values never crash the packer", () => {
  it("M7-07 a receipt outcome with status \"Unknown\" is skipped, not a TypeError", async () => {
    const tx = purchaseTx([outcome(GATE, [], "Unknown"), receiptOut(), payoutOut()]);
    expect(await code({ [D]: tx, [M]: registerTx() })).toBe("ok");
  });
  it("M7-07 a mandate transaction with a string status gives a PackError", async () => {
    const reg = { ...registerTx(), status: "Started" };
    const c = await code({ [D]: purchaseTx(), [M]: reg });
    expect(c.startsWith("other:")).toBe(false);
  });
});
