// Audit M8 (independent): README and runbook claims that can be checked offline.
// "M8-NN ..." tests assert the REQUIRED behaviour and fail while the finding is open.
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const read = (f) => readFileSync(resolve(ROOT, f), "utf8");

describe("audit M8: runbook order", () => {
  const book = read("docs/mainnet-runbook.md");
  const lockAt = book.indexOf("## 7. Lock");

  it("control: the runbook keeps the safe order deploy, register with USDC, verify, smoke test, lock", () => {
    const order = ["## 3. Deploy", "## 4. Register the gate with USDC", "## 5. Verify", "## 6. First purchase", "## 7. Lock"].map((h) => book.indexOf(h));
    expect(order.every((i) => i >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
  });

  it("M8-10 a release is bought AFTER the lock, so a mainnet release receipt can read Verified", () => {
    // The smoke purchase (step 6) is decided while the gate still has a full-access key, so the
    // checker's "The gate ran reviewed code when it decided" stays unknown for that receipt for good
    // (apps/checker/src/verify.ts, historicGate). README and runbook step 8 promise a green release.
    expect(lockAt).toBeGreaterThan(0);
    expect(book.slice(lockAt)).toMatch(/proof\.mjs (prepare|quote)/);
  });

  it("M8-11 examples/mainnet-gate.json exists before step 6 on the hardware-wallet path", () => {
    // proof.mjs reads examples/mainnet-gate.json at start; the runbook only says to write it in step 7.
    const firstWrite = book.search(/[Ww]rite[^.\n]*examples\/mainnet-gate\.json/);
    expect(firstWrite).toBeGreaterThan(0);
    expect(firstWrite, "the runbook asks for the gate record only after the smoke test").toBeLessThan(book.indexOf("## 6. First purchase"));
  });
});

describe("audit M8: README prerequisites", () => {
  it("M8-12 the stated Node version runs the scripts' TypeScript imports without flags (22.18 or newer)", () => {
    // pnpm dry-run imports .ts files directly. **Assumption:** Node strips types by default only from 22.18.0.
    const engines = JSON.parse(read("package.json")).engines.node;
    const m = /(\d+)\.(\d+)/.exec(engines) ?? [null, engines.replace(/\D/g, ""), "0"];
    expect(Number(m[1]) > 22 || (Number(m[1]) === 22 && Number(m[2]) >= 18), `engines.node is ${engines}`).toBe(true);
    expect(read("README.md")).not.toMatch(/Node 22 or newer/);
  });
});
