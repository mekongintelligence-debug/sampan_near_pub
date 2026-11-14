// Guards for the agent process (M4 threat review): it holds only a function-call key for
// gate.purchase, never the operator's full-access key, and never a mainnet account.
export const OPERATOR_SECRETS = ["NEAR_TESTNET_PRIVATE_KEY", "TG_TOKEN"] as const;
/** Any variable whose name looks like a credential (M4-CR3: a denylist of names is not enough). */
const SECRET_NAME = /(PRIVATE|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|API_?KEY|_KEY$|^KEY$)/i;

/** The agent process must not be able to reach the operator's secrets, or any other secret. */
export function assertAgentEnvironment(env: Record<string, string | undefined>): void {
  const leaked = Object.keys(env).filter((k) => env[k] !== undefined && (SECRET_NAME.test(k) || (OPERATOR_SECRETS as readonly string[]).includes(k)));
  if (leaked.length) throw new Error(`refusing to run: the agent process can see secrets (${leaked.join(", ")})`);
}

type AccessKey = { permission: unknown };
/** The key the agent holds must be a function-call key for exactly gate.purchase. */
export function assertFunctionCallOnly(key: AccessKey, gate: string): void {
  const p = key.permission as { FunctionCall?: { receiver_id?: string; method_names?: string[] } } | string;
  const fc = typeof p === "object" && p !== null ? p.FunctionCall : undefined;
  if (!fc) throw new Error("refusing to run: the agent key is not a function-call key");
  if (fc.receiver_id !== gate) throw new Error("refusing to run: the agent key is not limited to the gate");
  const m = fc.method_names ?? [];
  if (m.length !== 1 || m[0] !== "purchase") throw new Error("refusing to run: the agent key must allow only purchase");
  // A key without an allowance may spend the whole account balance on gas (M4-CR2).
  const allowance = (fc as { allowance?: string | null }).allowance;
  if (allowance == null) throw new Error("refusing to run: the agent key has no allowance limit");
}

/** Testnet only, for every account the agent touches. */
export function assertTestnetAccounts(accounts: string[]): void {
  for (const a of accounts) if (!/^[a-z0-9._-]{2,64}$/.test(a) || !a.endsWith(".testnet")) throw new Error("refusing to run: not a .testnet account");
}
