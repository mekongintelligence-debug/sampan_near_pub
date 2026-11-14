// Safety helpers for scripts that touch a network (M1 threat review).
// Testnet only: anything else stops the script before a single call is made.
const TESTNET_RPCS = new Set(["https://rpc.testnet.near.org", "https://test.rpc.fastnear.com"]);

export function assertTestnet({ networkId, rpcUrl, accounts }) {
  if (networkId !== "testnet") throw new Error(`refusing to run: network is ${networkId}, not testnet`);
  if (!TESTNET_RPCS.has(rpcUrl)) throw new Error("refusing to run: RPC is not a known testnet endpoint");
  accounts.forEach((a, i) => {
    // Never echo the value: a secret put in the wrong variable must not be printed (M1-08).
    if (typeof a !== "string" || !a.endsWith(".testnet")) throw new Error(`refusing to run: account #${i + 1} is not a .testnet account`);
  });
}

/** Remove anything that looks like a NEAR secret key from text before it is printed. */
export function redact(text) {
  return String(text)
    .replace(/(ed25519|secp256k1):[1-9A-HJ-NP-Za-km-z]{80,}/g, "$1:[redacted]")
    // near-api-js also holds the secret without a prefix (secretKey, extendedSecretKey) (M1-02).
    .replace(/[1-9A-HJ-NP-Za-km-z]{80,}/g, "[redacted]")
    .replace(/"(private_key|secretKey|extendedSecretKey|secret_key)"\s*:\s*"[^"]*"/g, '"$1":"[redacted]"');
}

/** Route every uncaught error through redact() before it is printed (M1-02, M1-08). */
export function installRedactingErrorHandlers() {
  const handler = (e) => { console.error("error: " + redact(e?.message ?? e)); process.exit(1); };
  process.on("uncaughtException", handler);
  process.on("unhandledRejection", handler);
}

/** Read the testnet key from the environment; never echo it. */
export function testnetKeyFromEnv(env = process.env) {
  const key = env.NEAR_TESTNET_PRIVATE_KEY;
  if (!key || !/^ed25519:[1-9A-HJ-NP-Za-km-z]{80,100}$/.test(key)) {
    throw new Error("NEAR_TESTNET_PRIVATE_KEY missing or not an ed25519 secret key");
  }
  return key;
}
