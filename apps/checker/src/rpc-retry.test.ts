// A3-02 regression: one dropped or throttled call used to end the whole check with "the RPC could not be
// reached" (a user on a fast connection saw it on the first call). Bounded retries, same host, only for
// transport failures and busy statuses; a real RPC answer is never retried.
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { Rpc, RpcError, RPC_RETRY, type FetchResponse } from "./rpc.ts";

const URL_ = "https://archival-rpc.testnet.near.org";
const ok = (result: unknown): FetchResponse => ({ ok: true, status: 200, json: async () => ({ jsonrpc: "2.0", id: "checker", result }) });
const status = (code: number): FetchResponse => ({ ok: false, status: code, json: async () => ({}) });
const rpcError = (name: string): FetchResponse => ({ ok: true, status: 200, json: async () => ({ jsonrpc: "2.0", id: "checker", error: { name: "HANDLER_ERROR", cause: { name } } }) });

let saved: number[];
beforeEach(() => { saved = RPC_RETRY.delaysMs; RPC_RETRY.delaysMs = [1, 1]; });
afterEach(() => { RPC_RETRY.delaysMs = saved; });

function scripted(steps: Array<FetchResponse | "fail">) {
  let calls = 0;
  const fetchFn = async () => { const s = steps[Math.min(calls++, steps.length - 1)]; if (s === "fail") throw new TypeError("Failed to fetch"); return s; };
  return { fetchFn: fetchFn as any, calls: () => calls };
}

describe("A3-02: bounded retry of a dropped or throttled call", () => {
  it("recovers from two network failures in a row", async () => {
    const f = scripted(["fail", "fail", ok({ chain_id: "testnet" })]);
    expect(await new Rpc(URL_, f.fetchFn).chainId()).toBe("testnet");
    expect(f.calls()).toBe(3);
  });
  it("recovers from a throttled (429) or busy (503) answer", async () => {
    const f = scripted([status(429), status(503), ok({ chain_id: "testnet" })]);
    expect(await new Rpc(URL_, f.fetchFn).chainId()).toBe("testnet");
    expect(f.calls()).toBe(3);
  });
  it("gives up after the retries and says the RPC could not be reached (3 attempts, no more)", async () => {
    const f = scripted(["fail"]);
    await expect(new Rpc(URL_, f.fetchFn).chainId()).rejects.toThrow(/could not be reached/);
    expect(f.calls()).toBe(3);
    const g = scripted([status(429)]);
    await expect(new Rpc(URL_, g.fetchFn).chainId()).rejects.toThrow(RpcError);
    expect(g.calls()).toBe(3);
  });
  it("never retries a real RPC answer, even an error answer", async () => {
    const f = scripted([rpcError("UNKNOWN_TRANSACTION"), ok({ chain_id: "testnet" })]);
    await expect(new Rpc(URL_, f.fetchFn).call("tx", {})).rejects.toThrow(/UNKNOWN_TRANSACTION/);
    expect(f.calls()).toBe(1);
  });
  it("with no delays configured it makes exactly one attempt", async () => {
    RPC_RETRY.delaysMs = [];
    const f = scripted(["fail", ok({ chain_id: "testnet" })]);
    await expect(new Rpc(URL_, f.fetchFn).chainId()).rejects.toThrow(/could not be reached/);
    expect(f.calls()).toBe(1);
  });
  it("retries only the host that was configured (no other URL is ever called)", async () => {
    const urls: string[] = [];
    const f: any = async (u: string) => { urls.push(u); if (urls.length < 3) throw new TypeError("x"); return ok({ chain_id: "testnet" }); };
    await new Rpc(URL_, f).chainId();
    expect(new Set(urls)).toEqual(new Set([URL_ + "/"]));
  });
});
