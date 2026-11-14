// Independent audit A2 (docs/audits/A2.md): README, user guide and disclosure claims against
// the code. Each "A2-NN ..." test asserts the REQUIRED behaviour, so it FAILS while its finding
// is open. "control: ..." tests pass now and must keep passing. No network, no keys.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const read = (f) => readFileSync(resolve(ROOT, f), "utf8");
const README = read("README.md");
const GUIDE = read("docs/USER-GUIDE.md");
const HACK = read("HACKATHON.md");
const GATE = read("contracts/gate/src/lib.rs");

// ---- A2-02 (Medium): "every refusal of an authenticated order is anchored" ------------------
// In `decide`, an authorised caller (the mandate's agent, or the buyer's account) is refused
// WITHOUT a receipt for: a repeated order ID, the order cap, no escrow, too little gas and
// "internal"; `purchase` refuses a malformed order and a stopped gate before `decide`. These
// leave only a `refused` event. README and the user guide claim otherwise.
describe("A2-02 refusals of authenticated orders that leave no anchored receipt", () => {
  it("control: the gate refuses authorised callers without an anchor for these reasons", () => {
    for (const reason of ["order_used", "order_cap", "no_escrow", "insufficient_gas"]) expect(GATE).toContain(`refuse("${reason}")`);
    expect(GATE).toMatch(/if self\.stopped \{\s*return refusal\("stopped"\);/);
    expect(GATE).toContain("fn unanchored(");
  });
  it("A2-02 the user guide does not say that refusals of agent orders always leave a receipt", () => {
    expect(GUIDE).not.toMatch(/always leave a receipt/i);
  });
  for (const [name, text] of [["README.md", README], ["docs/USER-GUIDE.md", GUIDE]]) {
    it(`A2-02 ${name} names the authenticated refusals that leave only an event`, () => {
      if (!/every refusal of an authenticated order/i.test(text) && !/Both are anchored/i.test(text)) return;
      // Required: the stated limit names at least the unfunded mandate and the order cap
      // next to the repeated order ID (the README mentions none of them).
      expect(text).toMatch(/(no escrow|unfunded|not (yet )?funded|nothing (is )?held)/i);
      expect(text).toMatch(/order (cap|limit)|orders per mandate/i);
      expect(text).toMatch(/(repeated|reused) order ID/i);
    });
  }
});

// ---- A2-03 (Medium): an accepted Medium item is missing from the README ---------------------
// MILESTONES A2 acceptance: "accepted Medium items are listed in the README". A1R-03 (Medium)
// was closed by a lead decision (max_mandates 100) that leaves the risk in place: a stranger can
// hold every open-mandate slot, or the whole total-escrow cap, for up to 24 hours with refundable
// deposits and their own money, which blocks new checkouts. M5-02 and A1R-11 are listed.
describe("A2-03 accepted Medium items in the README", () => {
  it("control: M5-02 is listed", () => {
    expect(README).toContain("M5-02");
  });
  it("A2-03 the README lists A1R-03 (caps can be held for a day, blocking new checkouts)", () => {
    expect(README).toContain("A1R-03");
  });
});

// ---- A2-05 (Low): commit hashes that will not exist in the public repository ----------------
// docs/gates.md (Gate 1): the public repository is created from the exported tree with a fresh
// history. HACKATHON.md cites the first commit by hash as the evidence for when work began; the
// public repository will not contain it.
describe("A2-05 disclosures that cite private history", () => {
  it("A2-05 HACKATHON.md either cites no commit hash or says the hashes refer to the private history", () => {
    if (!/`[0-9a-f]{7,40}`/.test(HACK)) return;
    expect(HACK).toMatch(/private (repository|history)/i);
  });
});

// ---- A2-06 (Low): user-guide statements that the code or the status contradict -------------
describe("A2-06 user guide wording", () => {
  it("control: the widget refuses live payments on mainnet", () => {
    expect(read("apps/checkout-widget/src/widget.ts")).toMatch(/if \(live && network !== "testnet"\) throw/);
  });
  it("A2-06 the shop snippet does not show a live mainnet configuration the widget refuses", () => {
    const snippet = GUIDE.match(/```html\n([\s\S]*?)```/)?.[1] ?? "";
    expect(/data-network="mainnet"/.test(snippet) && /data-mode="live"/.test(snippet)).toBe(false);
  });
  it("A2-06 the guide does not state the mainnet lock as done before it has happened", () => {
    // No mainnet gate exists yet (README status). "is to be locked" or an Assumption marker is fine.
    expect(GUIDE).not.toMatch(/has no owner after deployment: its keys are deleted/);
  });
});
