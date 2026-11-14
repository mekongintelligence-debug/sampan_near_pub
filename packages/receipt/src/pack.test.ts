// M7 abuse cases for the receipt packer: it must build only envelopes the chain supports, and
// refuse a transaction for another order, another mandate or another gate, a non-final or
// failed step, and lookalike events. Synthetic transactions shaped like NEAR RPC answers,
// built from the shared vectors.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { canonicalize, hashHex } from "@sampan/mandate";
import { base58 } from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import { packReceipt, PackError, type TxFetch } from "./pack.ts";

const DIR = resolve(import.meta.dirname, "../../../fixtures/vectors");
const vecText = (rel: string) => Buffer.from(JSON.parse(readFileSync(join(DIR, rel), "utf8")).input_b64, "base64").toString("utf8");
const GATE = JSON.parse(Buffer.from(JSON.parse(readFileSync(join(resolve(import.meta.dirname, "../../../fixtures/vectors"), "receipt_core/release.json"), "utf8")).input_b64, "base64").toString("utf8")).gate as string;
const h58 = (l: string) => base58.encode(sha256(new TextEncoder().encode(l)));
const D = h58("decision"), M = h58("mandate");
const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64");
const signedText = vecText("signed_mandate/nep413-valid.json");
const orderText = vecText("order/valid.json");
const core = JSON.parse(vecText("receipt_core/release.json"));
const coreHash = hashHex(canonicalize(core));
const orderId = JSON.parse(orderText).order_id;

function receiptLog(c = core, h = coreHash, executor = GATE, failed = false, event = "receipt") {
  return { outcome: { executor_id: executor, status: failed ? { Failure: {} } : { SuccessValue: "" }, logs: [`EVENT_JSON:${JSON.stringify({ standard: "sampan", version: "1.0.0", event, data: [{ order_id: orderId, core: c, core_hash: h }] })}`] } };
}
const payoutLog = (status = "done") => ({ outcome: { executor_id: GATE, status: { SuccessValue: "" }, logs: [`EVENT_JSON:${JSON.stringify({ standard: "sampan", version: "1.0.0", event: "payout", data: [{ order_id: orderId, mandate_hash: core.mandate_hash, status }] })}`] } });
const purchaseTx = (order = orderText, outcomes: any[] = [receiptLog(), payoutLog()], final = "FINAL") => ({
  final_execution_status: final, transaction: { receiver_id: GATE, actions: [{ FunctionCall: { method_name: "purchase", args: b64({ order }) } }] }, receipts_outcome: outcomes,
});
const registerTx = (signed = signedText, status: any = { SuccessValue: "" }) => ({ final_execution_status: "FINAL", status, transaction: { receiver_id: GATE, actions: [{ FunctionCall: { method_name: "register_mandate", args: b64({ signed_mandate: signed }) } }] }, receipts_outcome: [] });
const fetcher = (txs: Record<string, any>): TxFetch => async (h) => txs[h] ?? null;
const input = { gate: GATE, token: "usdc.testnet", decisionTx: D, mandateTx: M };
const code = async (txs: Record<string, any>, extra: object = {}) => {
  try { await packReceipt({ ...input, ...extra }, fetcher(txs)); return "ok"; } catch (e) { return e instanceof PackError ? e.code : `other:${(e as Error).message}`; }
};

describe("M7 receipt packer", () => {
  it("control: packs a release from the decision and registration transactions; the payout is the decision tx", async () => {
    const env = await packReceipt(input, fetcher({ [D]: purchaseTx(), [M]: registerTx() }));
    expect(env.core.decision).toBe("release");
    expect(env.tx).toEqual({ deposit: null, decision: D, payout: D });
  });
  it("a payout that did not complete is not recorded as the payout transaction", async () => {
    const env = await packReceipt(input, fetcher({ [D]: purchaseTx(orderText, [receiptLog(), payoutLog("failed")]), [M]: registerTx() }));
    expect(env.tx.payout).toBeNull();
  });
  it("a decision transaction for another order is refused (order_mismatch)", async () => {
    const other = JSON.stringify({ ...JSON.parse(orderText), order_id: "ee".repeat(32) });
    expect(await code({ [D]: purchaseTx(canonicalize(JSON.parse(other))), [M]: registerTx() })).toBe("order_mismatch");
  });
  it("a mandate transaction for another mandate is refused", async () => {
    const otherSigned = vecText("signed_mandate/erc191-valid-v01.json");
    expect(await code({ [D]: purchaseTx(), [M]: registerTx(otherSigned) })).toBe("mandate_mismatch");
  });
  it("non-final, missing, or failed steps are refused", async () => {
    expect(await code({ [D]: purchaseTx(orderText, [receiptLog()], "EXECUTED_OPTIMISTIC"), [M]: registerTx() })).toBe("not_final");
    expect(await code({ [M]: registerTx() })).toBe("no_decision_tx");
    expect(await code({ [D]: purchaseTx(orderText, [receiptLog(core, coreHash, GATE, true)]), [M]: registerTx() })).toBe("no_receipt_event");
  });
  it("a lookalike event from another contract, or two receipt events, is refused", async () => {
    expect(await code({ [D]: purchaseTx(orderText, [receiptLog(core, coreHash, "evil.testnet")]), [M]: registerTx() })).toBe("no_receipt_event");
    // Since M7-05 two decisions in one transaction need the order ID to choose one.
    expect(await code({ [D]: purchaseTx(orderText, [receiptLog(), receiptLog()]), [M]: registerTx() })).toBe("several_decisions");
  });
  it("an event whose core does not hash to its core_hash is refused", async () => {
    expect(await code({ [D]: purchaseTx(orderText, [receiptLog(core, "0".repeat(64))]), [M]: registerTx() })).not.toBe("ok");
  });
  it("an order inside a funding message must have gone through the gate's token", async () => {
    const fund = (receiver: string) => ({ final_execution_status: "FINAL", transaction: { receiver_id: receiver, actions: [{ FunctionCall: { method_name: "ft_transfer_call", args: b64({ receiver_id: GATE, amount: "1", msg: JSON.stringify({ mandate_hash: core.mandate_hash, order: orderText }) }) } }] }, receipts_outcome: [receiptLog()] });
    expect(await code({ [D]: fund("usdc.testnet"), [M]: registerTx() })).toBe("ok");
    expect(await code({ [D]: fund("fake-usdc.testnet"), [M]: registerTx() })).toBe("no_order");
  });
  it("an over-long note is refused", async () => {
    expect(await code({ [D]: purchaseTx(), [M]: registerTx() }, { note: "x".repeat(281) })).toBe("note");
  });
  it("M7-CR1: an order in a receipt created by 1Click's contracts (not a transaction action) is found", async () => {
    const delivery = {
      final_execution_status: "FINAL",
      transaction: { receiver_id: "intents.near", actions: [{ FunctionCall: { method_name: "execute_intents", args: b64({}) } }] },
      receipts: [{ receiver_id: "usdc.testnet", receipt: { Action: { actions: [{ FunctionCall: { method_name: "ft_transfer_call", args: b64({ receiver_id: GATE, amount: "1", msg: JSON.stringify({ mandate_hash: core.mandate_hash, order: orderText }) }) } }] } } }],
      receipts_outcome: [receiptLog()],
    };
    expect(await code({ [D]: delivery, [M]: registerTx() })).toBe("ok");
  });
  it("M7-CR3: a failed registration is not a source for the mandate", async () => {
    expect(await code({ [D]: purchaseTx(), [M]: registerTx(signedText, { Failure: {} }) })).toBe("mandate_tx_failed");
  });
  it("M7-CR7: a transfer to another receiver does not supply the order", async () => {
    const tx = { final_execution_status: "FINAL", transaction: { receiver_id: "usdc.testnet", actions: [{ FunctionCall: { method_name: "ft_transfer_call", args: b64({ receiver_id: "other.testnet", amount: "1", msg: JSON.stringify({ order: orderText }) }) } }] }, receipts_outcome: [receiptLog()] };
    expect(await code({ [D]: tx, [M]: registerTx() })).toBe("no_order");
  });
});
