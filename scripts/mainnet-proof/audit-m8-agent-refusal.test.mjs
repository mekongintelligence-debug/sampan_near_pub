// Audit M8 (independent): the person-run mainnet refusal example, offline.
// "M8-NN ..." tests assert the REQUIRED behaviour and fail while the finding is open.
import { describe, it, expect } from "vitest";
import { isAnchoredPayeeRefusal } from "./agent-refusal.mjs";

const ev = (failedIds) => ({ core: { rules: ["R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"].map((id) => ({ id, pass: !failedIds.includes(id) })) } });
const refused = { decision: "refuse", anchored: true };

describe("audit M8: agent-refusal success check", () => {
  it("control: an anchored refusal where only R8 failed counts", () => {
    expect(isAnchoredPayeeRefusal(refused, ev(["R8"]))).toBe(true);
  });

  it("M8-08 a refusal where the budget rule also failed (mandate not funded) is not reported as the R8 example", () => {
    expect(isAnchoredPayeeRefusal(refused, ev(["R7", "R8"]))).toBe(false);
  });

  it("M8-08 a refusal where the expiry or caller rule also failed is not reported as the R8 example", () => {
    expect(isAnchoredPayeeRefusal(refused, ev(["R3", "R8"]))).toBe(false);
    expect(isAnchoredPayeeRefusal(refused, ev(["R5", "R8"]))).toBe(false);
  });
});
