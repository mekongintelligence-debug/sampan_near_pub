// Minimal NEAR JSON-RPC client for the checker. Every request goes to the configured RPC
// URL only (the page's CSP enforces the same). All reads use `final` finality.
export type FetchResponse = { ok: boolean; json(): Promise<unknown>; body?: ReadableStream<Uint8Array> | null };
export type Fetch = (url: string, init: { method: string; headers: Record<string, string>; body: string }) => Promise<FetchResponse>;

export class RpcError extends Error {}

// Archival hosts by default: a regular RPC forgets transactions after about a day (audit M8-01), so
// the transaction checks of any older receipt would time out there. Both hosts are in the page's CSP.
export const DEFAULT_RPC: Record<"testnet" | "mainnet", string> = {
  testnet: "https://archival-rpc.testnet.near.org",
  mainnet: "https://archival-rpc.mainnet.near.org",
};
/** Hosts the page may contact (mirrored in the CSP of index.html by the build). */
export const ALLOWED_RPC_HOSTS = ["rpc.testnet.near.org", "rpc.mainnet.near.org", "test.rpc.fastnear.com", "rpc.fastnear.com", "archival-rpc.testnet.near.org", "archival-rpc.mainnet.near.org"];

export function checkRpcUrl(url: string): string {
  let u: URL;
  try { u = new URL(url); } catch { throw new RpcError("not a URL"); }
  // Default port and root path only (M6-08): exactly what the page's CSP allows.
  if (u.protocol !== "https:" || !ALLOWED_RPC_HOSTS.includes(u.hostname) || u.username || u.password || u.port !== "" || (u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) {
    throw new RpcError(`only these RPC hosts are allowed: ${ALLOWED_RPC_HOSTS.join(", ")}`);
  }
  return u.origin + u.pathname;
}

const MAX_RESPONSE = 4_000_000;

/** Read a JSON body, stopping as soon as it exceeds MAX_RESPONSE bytes (M6-CR7). */
async function readCapped(res: FetchResponse): Promise<unknown> {
  const reader = res.body?.getReader?.();
  if (!reader) return res.json(); // test doubles without a stream
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_RESPONSE) { await reader.cancel(); throw new RpcError("the RPC answer is too large"); }
    chunks.push(value);
  }
  const all = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) { all.set(c, at); at += c.length; }
  return JSON.parse(new TextDecoder().decode(all));
}

export class Rpc {
  readonly url: string;
  private readonly fetchFn: Fetch;
  constructor(url: string, fetchFn: Fetch) {
    this.url = checkRpcUrl(url);
    this.fetchFn = fetchFn;
  }
  async call(method: string, params: unknown): Promise<any> {
    let res;
    try {
      res = await this.fetchFn(this.url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: "checker", method, params }) });
    } catch {
      throw new RpcError("the RPC could not be reached");
    }
    let body: any;
    try { body = await readCapped(res); } catch (e) { throw e instanceof RpcError ? e : new RpcError("the RPC answered with something that is not JSON"); }
    if (!body || typeof body !== "object") throw new RpcError("the RPC answer is malformed");
    if (body.error) throw new RpcError(String(body.error?.cause?.name ?? body.error?.name ?? "RPC error"));
    if (body.result === undefined) throw new RpcError("the RPC answer has no result");
    return body.result;
  }
  async chainId(): Promise<string> {
    const r = await this.call("status", []);
    return String(r?.chain_id ?? "");
  }
  /** A view call at final finality; returns the parsed JSON result. */
  async view(account: string, method: string, args: unknown): Promise<any> {
    const args_base64 = btoa(JSON.stringify(args));
    const r = await this.call("query", { request_type: "call_function", finality: "final", account_id: account, method_name: method, args_base64 });
    if (!Array.isArray(r?.result)) throw new RpcError("view result is malformed");
    const text = new TextDecoder().decode(Uint8Array.from(r.result as number[]));
    return JSON.parse(text);
  }
  /** A transaction's final outcome; `null` if the RPC does not know it for this sender. */
  async tx(hash: string, sender: string): Promise<any | null> {
    try {
      return await this.call("tx", { tx_hash: hash, sender_account_id: sender, wait_until: "FINAL" });
    } catch (e) {
      if (e instanceof RpcError && /UNKNOWN_TRANSACTION|INVALID_TRANSACTION|TIMEOUT_ERROR/.test(e.message)) return null;
      throw e;
    }
  }
  /** The deployed contract's code hash (base58 sha256 of the wasm). */
  async codeHash(account: string): Promise<string> {
    const r = await this.call("query", { request_type: "view_account", finality: "final", account_id: account });
    if (typeof r?.code_hash !== "string") throw new RpcError("account view is malformed");
    return r.code_hash;
  }
  /** Permission of every access key ("FullAccess" or "FunctionCall") at final, or in a block. */
  async accessKeys(account: string, blockHash?: string): Promise<string[]> {
    const at = blockHash ? { block_id: blockHash } : { finality: "final" };
    const r = await this.call("query", { request_type: "view_access_key_list", account_id: account, ...at });
    if (!Array.isArray(r?.keys)) throw new RpcError("access key list is malformed");
    return r.keys.map((k: any) => (k?.access_key?.permission === "FullAccess" ? "FullAccess" : "FunctionCall"));
  }
  /** Code hash and key kinds of an account in a past block; null if the RPC has no history. */
  async historicGate(account: string, blockHash: string): Promise<{ codeHash: string; keys: string[] } | null> {
    try {
      const a = await this.call("query", { request_type: "view_account", account_id: account, block_id: blockHash });
      if (typeof a?.code_hash !== "string") throw new RpcError("account view is malformed");
      return { codeHash: a.code_hash, keys: await this.accessKeys(account, blockHash) };
    } catch (e) {
      if (e instanceof RpcError && /UNKNOWN_BLOCK|GARBAGE_COLLECTED_BLOCK|UNKNOWN_TRANSACTION|UNAVAILABLE_SHARD|NO_SYNCED_BLOCKS/.test(e.message)) return null;
      throw e;
    }
  }
  async block(hash: string): Promise<{ height: string; timestampNs: string }> {
    const r = await this.call("block", { block_id: hash });
    const h = r?.header;
    if (!h || typeof h.height !== "number" || typeof h.timestamp_nanosec !== "string") throw new RpcError("block is malformed");
    return { height: String(h.height), timestampNs: h.timestamp_nanosec };
  }
}
