// Independent audit A1-payments (docs/audits/A1-payments.md): exploit tests and positive
// controls for the 1Click side of the payment path. Audited commit: 51dac1d.
//
// Each "A1P-NN ..." test asserts the REQUIRED behaviour, so it FAILS while finding A1P-NN
// is open. Tests named "control: ..." are positive controls and pass today.
//
// No test here touches a network or a key. The 1Click scripts run unchanged in a child
// process with a `fetch` replacement (loaded with --import) that answers only
// https://1click.chaindefuser.com/v0/* from a local plan and refuses every other URL.
// Mandates are signed with throwaway keys derived from fixed test seeds.
import { describe, it, expect, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { canonicalize, erc191Hash, evmAddress, verifySignedMandate, parseOrder } from "../../packages/mandate/src/index.ts";

const ROOT = resolve(import.meta.dirname, "../..");
const tmp = mkdtempSync(join(tmpdir(), "a1p-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

// 1Click's server-side limit, observed with dry quotes on 6 Nov 2026 (`dry: true`, no
// deposit address): a 3,000-character customRecipientMsg is refused with HTTP 400
// "customRecipientMsg must be shorter than or equal to 1024 characters". The public
// OpenAPI spec does not state the limit.
const ONECLICK_MSG_LIMIT = 1024;
const USDC_NEAR = "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1";

// ---- A1P-01: the direct-checkout funding message does not fit 1Click's limit ---------

function smallestDirectCheckoutMsg() {
  // Best case for size: an EVM (ERC-191) buyer paying from Base, short mainnet account
  // names, one short item, a 1 USDC exact price. Real shops will be longer.
  const sk = sha256(new TextEncoder().encode("a1p-test-only-buyer-key"));
  const address = evmAddress(secp256k1.getPublicKey(sk, false));
  const mandate = {
    v: "sampan.mandate.v1", network: "mainnet", gate: "gate.sampan.near", buyer: `evm:${address}`,
    agent: null, asset: USDC_NEAR, max_amount: "1000000", payee: "shop.near", items: ["item-1"],
    expiry_ns: "1794873600000000000", nonce: "ab".repeat(32), refund_to: "buyer.near",
  };
  const rec = secp256k1.sign(erc191Hash(canonicalize(mandate)), sk, { prehash: false, format: "recovered", lowS: true });
  const signature = bytesToHex(new Uint8Array([...rec.subarray(1), 27 + rec[0]]));
  const signedMandate = canonicalize({ v: "sampan.signed-mandate.v1", mandate, standard: "erc191", signature });
  const verified = verifySignedMandate(new TextEncoder().encode(signedMandate)); // the real format
  const order = canonicalize({
    v: "sampan.order.v1", order_id: "cd".repeat(32), mandate_hash: verified.mandateHash,
    item: "item-1", amount: "1000000", asset: USDC_NEAR, payee: "shop.near",
  });
  parseOrder(new TextEncoder().encode(order));
  // The gate's FundingMsg (contracts/gate/src/lib.rs): {"signed_mandate": "...", "order": "..." | null}
  // Author adaptation after the A1 redesign (docs/audits/A1-payments.md, author response): the
  // Sampan relayer registers the signed mandate first (register_mandate), so the 1Click payment
  // names it by hash: {"mandate_hash": "...", "order": "..."}. The limit asserted is unchanged.
  return {
    withOrder: JSON.stringify({ mandate_hash: verified.mandateHash, order }),
    withoutOrder: JSON.stringify({ signed_mandate: signedMandate, order: null }),
  };
}

describe("A1P-01 direct checkout through 1Click", () => {
  it("A1P-01 the smallest direct-checkout funding message fits 1Click's customRecipientMsg limit", () => {
    const { withOrder } = smallestDirectCheckoutMsg();
    expect(
      withOrder.length,
      `funding msg with the order is ${withOrder.length} characters; 1Click refuses customRecipientMsg over ${ONECLICK_MSG_LIMIT}, ` +
        "so the direct checkout of ARCHITECTURE 3.4 cannot be quoted (its Assumption of about 3 KB is wrong)",
    ).toBeLessThanOrEqual(ONECLICK_MSG_LIMIT);
  });

  it("control: a funding message without an order and with one short item fits (agent-funding path only)", () => {
    const { withoutOrder } = smallestDirectCheckoutMsg();
    expect(withoutOrder.length).toBeLessThanOrEqual(ONECLICK_MSG_LIMIT);
  });
});

// ---- harness for the 1Click scripts -------------------------------------------------

const MOCK = `
import { readFileSync, appendFileSync } from "node:fs";
const plan = JSON.parse(readFileSync(process.env.A1P_PLAN, "utf8"));
globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  if (!u.startsWith("https://1click.chaindefuser.com/v0/")) throw new Error("audit harness: network refused " + u);
  const body = init.body ? JSON.parse(init.body) : null;
  appendFileSync(process.env.A1P_LOG, JSON.stringify({ url: u, method: init.method ?? "GET", body }) + "\\n");
  const reply = (status, j) => new Response(JSON.stringify(j), { status, headers: { "content-type": "application/json" } });
  if (u.endsWith("/quote")) {
    const live = body.dry === false;
    const quoteRequest = { ...body, ...(live ? plan.echo ?? {} : {}) };
    const quote = {
      amountIn: body.amount, minAmountIn: body.amount, amountOut: "999800", minAmountOut: "989800",
      amountOutFormatted: "0.9998", timeEstimate: 35,
      ...(live ? { depositAddress: "0x" + "d".repeat(40), deadline: body.deadline } : {}),
      ...(live ? plan.quote ?? {} : {}),
    };
    return reply(201, { correlationId: "c", timestamp: new Date().toISOString(), signature: "ed25519:mock", quoteRequest, quote });
  }
  return reply(404, { message: "not found" });
};
`;
const mockFile = join(tmp, "fetch-mock.mjs");
writeFileSync(mockFile, MOCK);

function runScript(script, args, { plan = {}, input = "" } = {}) {
  const dir = mkdtempSync(join(tmp, "run-"));
  const planFile = join(dir, "plan.json");
  const log = join(dir, "requests.log");
  writeFileSync(planFile, JSON.stringify(plan));
  writeFileSync(log, "");
  const r = spawnSync(process.execPath, ["--import", pathToFileURL(mockFile).href, join(ROOT, script), ...args], {
    cwd: ROOT, input, encoding: "utf8", timeout: 30_000,
    // Minimal environment: no secrets are passed to the child.
    env: { PATH: process.env.PATH, A1P_PLAN: planFile, A1P_LOG: log },
  });
  const requests = existsSync(log) ? readFileSync(log, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
  return { code: r.status, out: (r.stdout ?? "") + (r.stderr ?? ""), requests };
}

const RECIPIENT = "a1p-test.near";
const REFUND_TO = "0x8ba1f109551bD432803012645Ac136ddd64DBA72"; // EIP-55 checksummed (public test address)
const PHRASE = `1 USDC to ${RECIPIENT} refund ${REFUND_TO}\n`;
const quoteArgs = ["--recipient", RECIPIENT, "--refund-to", REFUND_TO, "--amount", "1"];
const showsDeposit = (out) => /Send exactly .* to: 0x/.test(out);

describe("1Click scripts (scripts/m1)", () => {
  it("control: the dry-quote script sends only dry quotes to 1Click and nothing else", () => {
    const r = runScript("scripts/m1/oneclick-dry-quotes.mjs", []);
    expect(r.code).toBe(0);
    expect(r.requests.length).toBe(7);
    for (const q of r.requests) {
      expect(q.url).toBe("https://1click.chaindefuser.com/v0/quote");
      expect(q.body.dry).toBe(true);
    }
    expect(r.out).not.toMatch(/depositAddress|0xdddd/);
  });

  it("control: the mainnet quote script asks for a live quote only after the typed confirmation", () => {
    const r = runScript("scripts/m1/mainnet-quote.mjs", quoteArgs, { input: "yes\n" });
    expect(r.code).toBe(1);
    expect(r.requests.map((q) => q.body?.dry)).toEqual([true]);
    expect(showsDeposit(r.out)).toBe(false);
  });

  it("control: the mainnet quote script shows the deposit address for a faithful live quote", () => {
    const r = runScript("scripts/m1/mainnet-quote.mjs", quoteArgs, { input: PHRASE });
    expect(r.code, r.out).toBe(0);
    expect(r.requests.map((q) => q.body?.dry)).toEqual([true, false]);
    expect(showsDeposit(r.out)).toBe(true);
  });

  it("control: the mainnet quote script refuses amounts above 2 USDC and non-mainnet recipients before any request", () => {
    for (const args of [
      ["--recipient", RECIPIENT, "--refund-to", REFUND_TO, "--amount", "2.000001"],
      ["--recipient", "a1p-test.testnet", "--refund-to", REFUND_TO],
      ["--recipient", RECIPIENT, "--refund-to", "0x8ba1f109551bD432803012645Ac136ddd64DBA73"], // bad checksum
    ]) {
      const r = runScript("scripts/m1/mainnet-quote.mjs", args, { input: PHRASE });
      expect(r.code).toBe(2);
      expect(r.requests).toEqual([]);
    }
  });

  it("control: a live quote with a swapped recipient or refund address is refused", () => {
    for (const echo of [{ recipient: "attacker.near" }, { refundTo: "0x" + "e".repeat(40) }]) {
      const r = runScript("scripts/m1/mainnet-quote.mjs", quoteArgs, { input: PHRASE, plan: { echo } });
      expect(r.code).toBe(1);
      expect(showsDeposit(r.out)).toBe(false);
    }
  });

  // A1P-05: the echo check skips fields that decide how much arrives, when, and how.
  const unchecked = {
    "slippageTolerance 100% in the live request": { echo: { slippageTolerance: 10000 } },
    "a customRecipientMsg added to the live request (ft_transfer_call to the recipient)": { echo: { customRecipientMsg: "{}" } },
    "deadline moved by a day": { echo: { deadline: new Date(Date.now() + 86_400_000).toISOString() } },
    "depositType INTENTS instead of ORIGIN_CHAIN": { echo: { depositType: "INTENTS" } },
    "minAmountOut of 1 unit (output not bounded)": { quote: { minAmountOut: "1" } },
    "quote.deadline a week later than requested": { quote: { deadline: new Date(Date.now() + 7 * 86_400_000).toISOString() } },
    "appFees taking 50% added to the live request": { echo: { appFees: [{ recipient: "fee.near", fee: 5000 }] } },
  };
  for (const [name, plan] of Object.entries(unchecked)) {
    it(`A1P-05 the mainnet quote script refuses a live quote with ${name}`, () => {
      const r = runScript("scripts/m1/mainnet-quote.mjs", quoteArgs, { input: PHRASE, plan });
      expect(showsDeposit(r.out), `deposit address shown although the live quote differs: ${name}`).toBe(false);
      expect(r.code).toBe(1);
    });
  }

  it("A1P-06 the mainnet quote script requires an EIP-55 checksummed refund address", () => {
    // All-lowercase input skips the checksum, so a one-character typo in the Base refund
    // address is accepted and echoed back; 1Click would refund to the typo.
    const typo = "0x8ba1f109551bd432803012645ac136ddd64dba73";
    const r = runScript("scripts/m1/mainnet-quote.mjs", ["--recipient", RECIPIENT, "--refund-to", typo], {
      input: `1 USDC to ${RECIPIENT} refund ${typo}\n`,
    });
    expect(r.requests, "a non-checksummed refund address was accepted and sent to 1Click").toEqual([]);
    expect(r.code).toBe(2);
  });
});
