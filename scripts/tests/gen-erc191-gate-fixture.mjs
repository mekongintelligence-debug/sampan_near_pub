#!/usr/bin/env node
// Prints the signed agentless ERC-191 mandate used by the gate test
// `a1p_10_erc191_direct_checkout_is_registered_paid_and_released` (contracts/gate/src/tests.rs).
// Throwaway test key from a fixed seed; the values match that test's constants.
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalize, erc191Hash, evmAddress, verifySignedMandate, toBytes } from "../../packages/mandate/src/index.ts";

const sk = sha256(new TextEncoder().encode("gate-test-only-erc191-buyer"));
const addr = evmAddress(secp256k1.getPublicKey(sk, false));
const mandate = {
  v: "sampan.mandate.v1", network: "testnet", gate: "gate.testnet", buyer: `evm:${addr}`, agent: null, asset: "usdc.testnet",
  max_amount: "25", payee: "shop.testnet", items: ["report-001"], expiry_ns: "2000000000000", nonce: "e1".repeat(32), refund_to: addr,
};
const rec = secp256k1.sign(erc191Hash(canonicalize(mandate)), sk, { prehash: false, format: "recovered", lowS: true });
const text = canonicalize({ v: "sampan.signed-mandate.v1", mandate, standard: "erc191", signature: bytesToHex(new Uint8Array([...rec.subarray(1), 27 + rec[0]])) });
const v = verifySignedMandate(toBytes(text));
console.log(JSON.stringify({ signed_mandate: text, mandate_hash: v.mandateHash, refund_to: addr }, null, 2));
