// Independent audit of M1 (docs/audits/M1.md). Every test here is an exploit or check for a
// finding and is EXPECTED TO FAIL until the finding is fixed. Test names carry the finding ID.
//
// Safety of these tests:
// - No real network. Scripts run in a child process with `fetch` (1Click) or `near-api-js`
//   (NEAR RPC) replaced by in-process mocks; the mocks refuse any unexpected host.
// - No real key. Children get a minimal environment with a fake, shape-valid key; the real
//   NEAR_TESTNET_PRIVATE_KEY is never passed on.
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { inspect } from "node:util";
import { Account, JsonRpcProvider, KeyPair } from "near-api-js";
import { assertTestnet, redact } from "./safety.mjs";

const HERE = import.meta.dirname;
const ROOT = resolve(HERE, "../..");
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const FAKE_KEY = "ed25519:" + Array.from({ length: 88 }, (_, i) => B58[(i * 11 + 3) % 58]).join("");

let dir;
const url = (f) => pathToFileURL(join(dir, f)).href;

// ---------- mocks written to a temp dir at test time ----------
const FETCH_MOCK = `
const S = JSON.parse(process.env.AUDIT_SCENARIO || "{}");
globalThis.fetch = async (u, init) => {
  u = String(u);
  if (!u.startsWith("https://1click.chaindefuser.com/")) throw new Error("audit mock: unexpected host");
  const body = init && init.body ? JSON.parse(init.body) : null;
  process.stderr.write("MOCKREQ " + JSON.stringify({ u, body }) + "\\n");
  const live = body && body.dry === false;
  const o = (live ? S.live : S.dry) || {};
  const json = {
    quoteRequest: { ...body, ...(o.quoteRequest || {}) },
    quote: { amountIn: body && body.amount, amountOutFormatted: "0.99", depositAddress: live ? "0xDEPOSIT0000000000000000000000000000000001" : undefined,
             deadline: body && body.deadline, ...(o.quote || {}) },
    signature: "ed25519:mock",
  };
  return new Response(JSON.stringify(json), { status: 201, headers: { "content-type": "application/json" } });
};
`;

const NEAR_MOCK = `
const S = JSON.parse(process.env.AUDIT_SPIKE || "{}");
const ENVKEY = process.env.NEAR_TESTNET_PRIVATE_KEY;
const log = (m) => process.stderr.write("MOCKCALL " + m + "\\n");
const fail = () => { throw new Error(S.failWith || "fetch failed"); };
const ok = () => ({ transaction: { hash: "11111111111111111111111111111111111111111111" }, status: { SuccessValue: "" } });
let balCalls = 0;
export class JsonRpcProvider {
  constructor() {}
  async viewAccount() { return {}; }
  async callFunction({ method }) {
    if (method === "ft_total_supply") return "1000000000";
    if (method === "ft_balance_of") { if (S.balanceThrows) throw new Error("fetch failed"); return String(balCalls++ === 0 ? 0 : 2500000); }
    return null;
  }
}
export const KeyPair = {
  fromString: () => ({ getPublicKey: () => ({ toString: () => "ed25519:PUB" }) }),
  fromRandom: () => { const id = "ed25519:FC" + Math.random(); return { getPublicKey: () => ({ toString: () => id + "pub" }), toString: () => id }; },
};
export class Account {
  constructor(id, provider, key) { this.id = id; this.key = key; }
  get fc() { return this.key !== ENVKEY; }
  async createSubAccount() { return ok(); }
  async deployContract() { return ok(); }
  async callFunctionRaw({ contractId, methodName, deposit }) {
    log(this.id + " " + methodName);
    if (this.fc) return contractId.startsWith("gate.") && methodName === "purchase" && !deposit ? ok() : fail();
    if (methodName === "purchase") return fail(); // buyer calling purchase
    return ok();
  }
  async addFunctionCallAccessKey() { log("addFunctionCallAccessKey"); return ok(); }
  async transfer() { return this.fc ? fail() : ok(); }
  async addFullAccessKey() { return this.fc ? fail() : ok(); }
  async deleteKey() { log("deleteKey"); return ok(); }
}
`;

const FS_MOCK = `
import * as real from "fs";
export const readFileSync = (p, ...a) => String(p).endsWith(".wasm") ? Buffer.from([0]) : real.readFileSync(p, ...a);
`;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "audit-m1-"));
  writeFileSync(join(dir, "fetch-mock.mjs"), FETCH_MOCK);
  writeFileSync(join(dir, "near-mock.mjs"), NEAR_MOCK);
  writeFileSync(join(dir, "fs-mock.mjs"), FS_MOCK);
  writeFileSync(join(dir, "hooks.mjs"), `
export async function resolve(spec, ctx, next) {
  if (spec === "near-api-js") return { url: ${JSON.stringify(url("near-mock.mjs"))}, shortCircuit: true };
  if (spec === "node:fs" && ctx.parentURL && ctx.parentURL.endsWith("/gate2-spike.mjs")) return { url: ${JSON.stringify(url("fs-mock.mjs"))}, shortCircuit: true };
  return next(spec, ctx);
}`);
  writeFileSync(join(dir, "register.mjs"), `import { register } from "node:module"; register(${JSON.stringify(url("hooks.mjs"))});`);
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));

// Minimal environment: never pass the real key or other secrets to a child.
const baseEnv = () => ({ PATH: process.env.PATH, HOME: process.env.HOME });

function runQuote(args, { input = "", scenario = {} } = {}) {
  const r = spawnSync(process.execPath, ["--import", url("fetch-mock.mjs"), join(HERE, "mainnet-quote.mjs"), ...args], {
    input, encoding: "utf8", timeout: 20000, env: { ...baseEnv(), AUDIT_SCENARIO: JSON.stringify(scenario) },
  });
  const reqs = (r.stderr.match(/^MOCKREQ .*$/gm) ?? []).map((l) => JSON.parse(l.slice(8)));
  return { ...r, reqs, live: reqs.filter((q) => q.body?.dry === false) };
}

function runSpike(spike = {}, env = {}) {
  const r = spawnSync(process.execPath, ["--import", url("register.mjs"), join(HERE, "gate2-spike.mjs")], {
    encoding: "utf8", timeout: 30000,
    env: { ...baseEnv(), NEAR_TESTNET_ACCOUNT_ID: "audit-fake.testnet", NEAR_TESTNET_PRIVATE_KEY: FAKE_KEY, AUDIT_SPIKE: JSON.stringify(spike), ...env },
  });
  return { ...r, calls: (r.stderr.match(/^MOCKCALL .*$/gm) ?? []).map((l) => l.slice(9)) };
}

const RECIP = "alice.near";
// EIP-55 checksummed: since A1P-06 the script refuses addresses without a checksum.
const REFUND = "0x8ba1f109551bD432803012645Ac136ddd64DBA72";

// ---------------------------------------------------------------------------------------
describe("M1-01 gate2-spike counts any error as an expected 'must fail' outcome", () => {
  it("M1-01: a network error on every must-fail call must not report 'all outcomes as expected'", () => {
    // Mock: the agent key is NOT restricted at all; every forbidden call just hits a network error.
    const r = runSpike({ failWith: "fetch failed" });
    expect(r.stdout).toContain("PASS"); // sanity: the script ran under the mock
    expect(r.stdout).not.toContain("Gate 2: all outcomes as expected");
    expect(r.status).not.toBe(0);
  }, 40000);

  it("M1-01: a must-fail step must record the protocol reason it failed for (e.g. H fails for gas, not the agent check)", () => {
    const r = runSpike({ failWith: "Exceeded the prepaid gas" });
    const results = JSON.parse(/RESULTS_JSON (.*)$/m.exec(r.stdout)[1]);
    const h = results.find((x) => x.name.startsWith("H."));
    // Expected after a fix: the step is UNEXPECTED unless the failure names the gate's refusal.
    expect(h.expected === h.outcome && !/only the agent/.test(h.detail)).toBe(false);
  }, 40000);
});

describe("M1-02 redact() misses the secret key in the forms near-api-js holds it", () => {
  it("M1-02: redact(inspect(Account)) must not contain the secret", () => {
    const kp = KeyPair.fromRandom("ed25519");
    const secret = kp.toString().slice("ed25519:".length);
    const acc = new Account("x.testnet", new JsonRpcProvider({ url: "https://rpc.testnet.near.org" }), kp.toString());
    const out = redact(inspect(acc, { depth: 8 }));
    expect(out.includes(secret)).toBe(false);
  });

  it("M1-02: redact() must remove an unprefixed extendedSecretKey / secretKey", () => {
    const kp = KeyPair.fromRandom("ed25519");
    const out = redact(`{"secretKey":"${kp.secretKey}","extendedSecretKey":"${kp.extendedSecretKey}"}`);
    expect(out.includes(kp.extendedSecretKey)).toBe(false);
    expect(out.includes(kp.secretKey)).toBe(false);
  });
});

describe("M1-03 mainnet-quote.mjs trusts the live quote response", () => {
  it("M1-03: a live quote whose echoed recipient, refund address or amount differ from the request must be refused", () => {
    // Author's note: the confirmation now includes the refund address (fix of M1-04).
    const r = runQuote(["--recipient", RECIP, "--refund-to", REFUND, "--amount", "1"], {
      input: `1 USDC to ${RECIP} refund ${REFUND}\n`,
      scenario: { live: { quoteRequest: { recipient: "attacker.near", refundTo: "0x" + "ee".repeat(20), amount: "2000000" }, quote: { amountIn: "2000000" } } },
    });
    expect(r.live.length).toBe(1); // the live quote was requested (mocked)
    expect(r.stdout).not.toContain("0xDEPOSIT"); // must not tell the person to pay it
  });
});

describe("M1-04 confirmation does not bind the refund address", () => {
  it("M1-04: the typed confirmation must include the refund address", () => {
    const r = runQuote(["--recipient", RECIP, "--refund-to", REFUND, "--amount", "1"], { input: `1 USDC to ${RECIP}\n` });
    // A live quote was requested after confirming only amount and recipient.
    expect(r.live.length === 1 && !r.stdout.includes(REFUND)).toBe(false);
  });
});

describe("M1-05 amount is rounded silently; displayed and quoted amounts differ", () => {
  for (const amt of ["1.0000004", "0.0000001", "1.9999999"]) {
    it(`M1-05: --amount ${amt} (more than 6 decimals) must be refused before any request`, () => {
      const r = runQuote(["--recipient", RECIP, "--refund-to", REFUND, "--amount", amt], { input: `${amt} USDC to ${RECIP}\n` });
      expect(r.reqs.length).toBe(0);
      expect(r.status).toBe(2);
    });
  }
});

describe("M1-06 recipient check accepts invalid NEAR account IDs", () => {
  for (const bad of ["..near", "-.near", "a..b.near", "_x.near", "a.-.near"]) {
    it(`M1-06: --recipient ${bad} must be refused before any request`, () => {
      const r = runQuote(["--recipient", bad, "--refund-to", REFUND, "--amount", "1"], { input: `1 USDC to ${bad}\n` });
      expect(r.reqs.length).toBe(0);
      expect(r.status).toBe(2);
    });
  }
});

describe("M1-07 refund address has no EIP-55 checksum check", () => {
  it("M1-07: a mixed-case address with a wrong checksum must be refused", () => {
    // Correct EIP-55 form is 0x8ba1f109551bD432803012645Ac136ddd64DBA72; one letter's case flipped.
    const bad = "0x8ba1f109551bD432803012645Ac136ddd64DBa72";
    const r = runQuote(["--recipient", RECIP, "--refund-to", bad, "--amount", "1"], { input: `1 USDC to ${RECIP}\n` });
    expect(r.reqs.length).toBe(0);
    expect(r.status).toBe(2);
  });
});

describe("M1-08 testnet guard echoes a misplaced secret", () => {
  it("M1-08: assertTestnet error must not contain a secret put in NEAR_TESTNET_ACCOUNT_ID by mistake", () => {
    let msg = "";
    try { assertTestnet({ networkId: "testnet", rpcUrl: "https://rpc.testnet.near.org", accounts: [FAKE_KEY] }); } catch (e) { msg = e.message; }
    expect(msg).not.toBe("");
    expect(msg).not.toContain(FAKE_KEY.slice(8));
  });

  it("M1-08: gate2-spike run with the key in the account variable must not print the key", () => {
    const r = runSpike({}, { NEAR_TESTNET_ACCOUNT_ID: FAKE_KEY });
    expect(r.status).not.toBe(0);
    expect(r.stdout + r.stderr).not.toContain(FAKE_KEY.slice(8));
  });
});

describe("M1-09 agent function-call key is not deleted when the run aborts", () => {
  it("M1-09: an RPC error after the key is added must still delete the key", () => {
    const r = runSpike({ balanceThrows: true });
    expect(r.calls).toContain("addFunctionCallAccessKey");
    expect(r.calls).toContain("deleteKey");
  }, 40000);
});

describe("M1-10 docs/gates.md conclusions stated more strongly than tested", () => {
  const gates = readFileSync(join(ROOT, "docs/gates.md"), "utf8");
  it("M1-10: Gate 4 'cannot route confidentially' is from the spec only and must be marked Assumption", () => {
    const line = gates.split("\n").find((l) => l.includes("funds cannot route confidentially"));
    expect(line).toMatch(/Assumption/);
  });
  it("M1-10: Gate 2 row H must not claim 'Refused by the gate' when the evidence is a bare trap", () => {
    const row = gates.split("\n").find((l) => l.startsWith("| Buyer (not the agent) calls"));
    expect(row).not.toMatch(/Refused by the gate \| contract trap/);
  });
});

describe("M1-11 deposit attribution: order ID in msg is unauthenticated", () => {
  it("M1-11: docs/gates.md Q12 must state that ft_on_transfer msg/sender are not proof of who paid", () => {
    const q12 = readFileSync(join(ROOT, "docs/gates.md"), "utf8").split("## Deposit attribution (Q12)")[1].split("\n## ")[0];
    expect(q12).toMatch(/untrusted|unauthenticated|anyone can|spoof/i);
  });
});
