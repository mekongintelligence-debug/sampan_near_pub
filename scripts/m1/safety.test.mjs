import { describe, it, expect } from "vitest";
import { assertTestnet, redact, testnetKeyFromEnv } from "./safety.mjs";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const fakeSecret = () => "ed25519:" + Array.from({ length: 88 }, (_, i) => B58[(i * 7) % 58]).join("");

describe("M1 safety", () => {
  const ok = { networkId: "testnet", rpcUrl: "https://rpc.testnet.near.org", accounts: ["a.sampan.testnet"] };
  it("accepts testnet", () => expect(() => assertTestnet(ok)).not.toThrow());
  it("refuses mainnet network, mainnet RPC and .near accounts", () => {
    expect(() => assertTestnet({ ...ok, networkId: "mainnet" })).toThrow(/not testnet/);
    expect(() => assertTestnet({ ...ok, rpcUrl: "https://rpc.mainnet.near.org" })).toThrow(/not a known testnet/);
    expect(() => assertTestnet({ ...ok, accounts: ["gate.sampan.near"] })).toThrow(/not a .testnet/);
    expect(() => assertTestnet({ ...ok, accounts: [undefined] })).toThrow();
  });
  it("redacts secret keys and private_key fields", () => {
    const s = fakeSecret();
    const out = redact(`error with ${s} and {"private_key": "${s}"}`);
    expect(out).not.toContain(s.slice(8));
    expect(out).toContain("ed25519:[redacted]");
  });
  it("keeps public keys short enough not to be mistaken for secrets", () => {
    expect(redact("ed25519:FVXWiqjgKL4aF28cdH8VzgtAXhYxyFSrvnekFnjESWCX")).toContain("FVXW");
  });
  it("reads the key only from NEAR_TESTNET_PRIVATE_KEY and validates its shape", () => {
    expect(testnetKeyFromEnv({ NEAR_TESTNET_PRIVATE_KEY: fakeSecret() })).toMatch(/^ed25519:/);
    expect(() => testnetKeyFromEnv({})).toThrow(/missing/);
    expect(() => testnetKeyFromEnv({ NEAR_TESTNET_PRIVATE_KEY: "ed25519:short" })).toThrow();
    expect(() => testnetKeyFromEnv({ EAR_TESTNET_PRIVATE_KEY: fakeSecret() })).toThrow();
  });
});
