// Known gate deployments, per network (M6 self-review M6-CR1). A receipt is green only if its
// gate is one of these accounts AND the account runs one of the listed contract builds AND
// the gate's own configuration names the listed settlement token. Otherwise anyone could
// deploy a look-alike contract that answers the checker's questions with "release".
// Code hash = base58(sha256(wasm)) of `make wasm-release`; reproduce it from the tagged source.
export interface KnownGate {
  account: string; codeHashes: string[]; token: string; label: string;
  /** Block at which every key was deleted (the lock). A decision strictly after it (the lock block itself is ambiguous, A2F-02) cannot have run other code (A2-01). */
  lockedAtBlock?: number;
}

export const KNOWN_GATES: Record<"testnet" | "mainnet", KnownGate[]> = {
  testnet: [
    {
      account: "gate-m3.sampan-trust-01.testnet",
      codeHashes: [
        "2ZCcVoRjrCmLcdmHd2B8cnzFJEyT88ozz1AnWa3pVQkA", // contract after audit A1R fixes (deployed 7 Nov 2026, 08:5x UTC)
        "PgEuTpCVtCZ4xWEJ97Qa6wMYCqUspFd2VRVu2sNDGMj", // contract after audit A1 fixes (receipts 7 Nov, 07:40-08:50 UTC)
        "HkChsGpdxRfLrYjHigEAwLK8JeqY96tJwc55rGHJTLcV", // contract after audit M3 fixes (receipts made before 7 Nov)
      ],
      token: "token.sampan-trust-01.testnet", // mock NEP-141 test token, not real money
      label: "Sampan test gate (testnet, test token)",
    },
  ],
  mainnet: [], // added with the reviewed mainnet deployment (M5, after A1)
};
