// Sampan relayer (M5, decided after audit A1-payments A1P-01): it registers a buyer's signed
// direct-checkout mandate on the gate, attaching the refundable storage deposit, so that the
// 1Click payment can carry only {"mandate_hash","order"}.
//
// The relayer is not trusted with money. It cannot sign mandates, change them or move tokens:
// the gate verifies the buyer's signature again and refuses anything it would refuse. What
// the relayer spends is NEAR for deposits, returned (less what each mandate leaves behind)
// when the mandate closes. This policy keeps that spend small and refuses mandates the
// checkout would never produce, so a stranger cannot use the relayer to lock its balance.
import { verifySignedMandate, toBytes, type VerifiedMandate } from "@sampan/mandate";

export interface Policy {
  network: "testnet" | "mainnet";
  gate: string;
  asset: string;
  /** Merchants that use the checkout. A mandate paying anyone else is refused. */
  payees: ReadonlySet<string>;
  /** Highest price the checkout offers, in token base units. */
  maxPrice: bigint;
  /** The gate's max_lifetime_ns, in ms. */
  maxLifetimeMs: number;
  /** Shortest lifetime the checkout produces: the quote deadline plus the settlement margin. */
  minLifetimeMs: number;
}

export const MAX_BODY_BYTES = 8 * 1024;
export const MAX_LIVE_PER_CLIENT = 2;
/** The widget builds 2-hour mandates; 5 minutes of clock skew, never the gate's full 24 h (M5-03). */
export const MAX_CHECKOUT_LIFETIME_MS = 2 * 3_600_000 + 5 * 60_000;

export type Check = { ok: true; verified: VerifiedMandate } | { ok: false; reason: string };

/** Decide whether the relayer pays the deposit for this signed mandate. Never throws. */
export function checkMandate(signedText: unknown, policy: Policy, nowMs: number): Check {
  if (typeof signedText !== "string" || signedText.length > MAX_BODY_BYTES) return { ok: false, reason: "invalid" };
  let verified: VerifiedMandate;
  try {
    verified = verifySignedMandate(toBytes(signedText));
  } catch {
    return { ok: false, reason: "invalid" };
  }
  const m = verified.mandate;
  if (m.network !== policy.network) return { ok: false, reason: "wrong_network" };
  if (m.gate !== policy.gate) return { ok: false, reason: "wrong_gate" };
  if (m.asset !== policy.asset) return { ok: false, reason: "wrong_asset" };
  // Agent mandates are registered by the buyer's own wallet, not by Sampan.
  if (m.agent !== null) return { ok: false, reason: "not_direct_checkout" };
  if (!policy.payees.has(m.payee)) return { ok: false, reason: "unknown_payee" };
  if (BigInt(m.max_amount) > policy.maxPrice) return { ok: false, reason: "price_too_high" };
  const expiryMs = Number(BigInt(m.expiry_ns) / 1_000_000n);
  if (expiryMs - nowMs > Math.min(policy.maxLifetimeMs, MAX_CHECKOUT_LIFETIME_MS)) return { ok: false, reason: "lifetime_too_long" };
  if (expiryMs - nowMs < policy.minLifetimeMs) return { ok: false, reason: "lifetime_too_short" };
  if (m.refund_to === policy.gate || m.payee === policy.gate) return { ok: false, reason: "refund_account" }; // A1R re-verification (Info)
  if (m.buyer.startsWith("evm:") && m.refund_to !== m.buyer.slice(4)) return { ok: false, reason: "refund_account" };
  return { ok: true, verified };
}

/** Per-client and global limits on what the relayer pays for. */
export class Limits {
  private recent = new Map<string, number[]>();
  /** Expiry (ms) of each mandate a client got registered: at most MAX_LIVE_PER_CLIENT live (M5-03). */
  private held = new Map<string, number[]>();
  private perClientPerHour: number;
  private maxOpen: number;
  constructor(perClientPerHour: number, maxOpen: number) {
    this.perClientPerHour = perClientPerHour;
    this.maxOpen = maxOpen;
  }

  /** Record one request from `client`; false when over the hourly limit. */
  allow(client: string, nowMs: number): boolean {
    const hourAgo = nowMs - 3_600_000;
    const times = (this.recent.get(client) ?? []).filter((t) => t > hourAgo);
    if (times.length >= this.perClientPerHour) {
      this.recent.set(client, times);
      return false;
    }
    if (!this.recent.has(client) && this.recent.size >= 10_000) {
      // Bounded memory without resetting anyone's count: drop clients idle for an hour,
      // and refuse new clients while the table is still full (fail closed).
      for (const [k, ts] of this.recent) if (!ts.some((t) => t > hourAgo)) this.recent.delete(k);
      if (this.recent.size >= 10_000) return false;
    }
    times.push(nowMs);
    this.recent.set(client, times);
    return true;
  }

  /** M5-03: one client holds at most MAX_LIVE_PER_CLIENT live registrations. */
  holds(client: string, nowMs: number): boolean {
    const live = (this.held.get(client) ?? []).filter((e) => e > nowMs);
    this.held.set(client, live);
    if (live.length === 0) this.held.delete(client);
    return live.length < MAX_LIVE_PER_CLIENT;
  }
  hold(client: string, expiryMs: number): void {
    if (this.held.size >= 10_000 && !this.held.has(client)) return;
    this.held.set(client, [...(this.held.get(client) ?? []), expiryMs]);
  }

  /** The gate's own count of open mandates must leave room (the relayer never fills the cap). */
  roomFor(openMandates: number): boolean {
    return openMandates < this.maxOpen;
  }
}

export interface Registrar {
  openMandates(): Promise<number>;
  /** M5-7: refund_to must exist on NEAR (final view) before the deposit is paid. */
  accountExists(account: string): Promise<boolean>;
  register(signedText: string): Promise<{ registered: boolean; reason?: string }>;
}

export type Answer = { status: number; body: { registered: boolean; mandate_hash?: string; reason?: string } };

// Registrations run one at a time, so the open-mandate check and the registration cannot
// interleave between requests (M5 self-review: concurrent requests could fill the cap).
let queue: Promise<unknown> = Promise.resolve();
function serial<T>(f: () => Promise<T>): Promise<T> {
  const next = queue.then(f, f);
  queue = next.catch(() => undefined);
  return next;
}

/** Handle one registration request. The body is untrusted; only fixed reason codes go back. */
export async function handle(body: unknown, client: string, deps: { policy: Policy; limits: Limits; registrar: Registrar; nowMs: number }): Promise<Answer> {
  if (!deps.limits.allow(client, deps.nowMs)) return { status: 429, body: { registered: false, reason: "rate_limited" } };
  const text = typeof body === "object" && body !== null ? (body as { signed_mandate?: unknown }).signed_mandate : undefined;
  const c = checkMandate(text, deps.policy, deps.nowMs);
  if (!c.ok) return { status: 400, body: { registered: false, reason: c.reason } };
  if (!deps.limits.holds(client, deps.nowMs)) return { status: 429, body: { registered: false, reason: "rate_limited" } };
  if (!(await deps.registrar.accountExists(c.verified.mandate.refund_to))) return { status: 400, body: { registered: false, reason: "refund_account_missing" } };
  const r = await serial(async () => {
    if (!deps.limits.roomFor(await deps.registrar.openMandates())) return null;
    return deps.registrar.register(text as string);
  });
  if (r === null) return { status: 503, body: { registered: false, reason: "busy" } };
  if (r.registered) deps.limits.hold(client, Number(BigInt(c.verified.mandate.expiry_ns) / 1_000_000n));
  const hash = c.verified.mandateHash;
  if (r.registered || r.reason === "already_registered") return { status: 200, body: { registered: true, mandate_hash: hash } };
  const reason = /^[a-z_]{1,40}$/.test(r.reason ?? "") ? r.reason : "refused";
  return { status: 409, body: { registered: false, mandate_hash: hash, reason } };
}

/** Mandates the relayer registered, closed after expiry so its deposits come back (M5-03). */
export class Sweeper {
  private open = new Map<string, number>();
  add(mandateHash: string, expiryMs: number): void {
    this.open.set(mandateHash, expiryMs);
  }
  /** Hashes to `refund` now (expired at least `graceMs` ago); kept until the gate says closed. */
  due(nowMs: number, graceMs = 60_000): string[] {
    return [...this.open].filter(([, e]) => e + graceMs <= nowMs).map(([h]) => h);
  }
  done(mandateHash: string): void {
    this.open.delete(mandateHash);
  }
}
