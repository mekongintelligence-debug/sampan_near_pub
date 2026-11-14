// Labelled agent-demo fixtures (fixtures/attacks/agent-demo/). The page text is DATA: this
// module never interprets, prints or forwards it. It returns only the structured fields
// the scripted agent needs, checked against strict grammars.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalize, grammar as g, FormatError, type Json } from "../../../packages/mandate/src/index.ts";

export interface Fixture {
  id: string;
  label: "attack" | "control";
  proposes: { item: string; payee: string; amount: string; asset: string };
  expected: { decision: "release" | "refuse"; failing: string[] };
}
export interface Accounts { payee: string; attacker: string; token: string; fakeToken: string }

const KEYS = ["id", "label", "technique", "page", "agent_proposes", "expected"] as const;
const ID = /^(inj|ctl)-\d\d-[a-z0-9-]{1,48}$/;
const RULE = /^R[1-9]$/;

/** Replace the placeholders in an account field; anything else must already be an account. */
export function resolveAccount(text: string, a: Accounts): string {
  const map: Record<string, string> = { "{{PAYEE}}": a.payee, "{{ATTACKER}}": a.attacker, "{{TOKEN}}": a.token, "{{FAKE_TOKEN}}": a.fakeToken };
  return map[text] ?? text;
}

export function parseFixture(raw: string, a: Accounts): Fixture {
  const v = JSON.parse(raw) as Json;
  const o = g.closedObject(v, "fixture", KEYS);
  const id = g.str(o.id, "fixture.id");
  if (!ID.test(id)) throw new FormatError("schema", "fixture.id: bad format");
  const label = g.str(o.label, "fixture.label");
  if (label !== "attack" && label !== "control") throw new FormatError("schema", "fixture.label: attack or control");
  if (label === "attack" !== id.startsWith("inj-")) throw new FormatError("schema", "fixture.id prefix does not match its label");
  g.str(o.technique, "fixture.technique");
  g.str(o.page, "fixture.page"); // present, never read further
  const p = g.closedObject(o.agent_proposes, "fixture.agent_proposes", ["item", "payee", "amount", "asset"]);
  const proposes = {
    item: g.itemId(p.item, "agent_proposes.item"),
    payee: g.account(resolveAccount(g.str(p.payee, "agent_proposes.payee"), a), "agent_proposes.payee"),
    amount: g.amount(p.amount, "agent_proposes.amount"),
    asset: g.account(resolveAccount(g.str(p.asset, "agent_proposes.asset"), a), "agent_proposes.asset"),
  };
  const e = g.closedObject(o.expected, "fixture.expected", ["decision", "failing"]);
  const decision = g.str(e.decision, "expected.decision");
  if (decision !== "release" && decision !== "refuse") throw new FormatError("schema", "expected.decision");
  if (!Array.isArray(e.failing)) throw new FormatError("schema", "expected.failing");
  const failing = e.failing.map((r) => {
    const s = g.str(r, "expected.failing[]");
    if (!RULE.test(s)) throw new FormatError("schema", "expected.failing[]: R1..R9");
    return s;
  });
  if ((decision === "release") !== (failing.length === 0)) throw new FormatError("inconsistent", "release iff no rule fails");
  // Controls must be released. Attacks are refused, except known misses: injections that
  // stay inside the signed mandate, which the gate releases by design (audit M4-08).
  if (label === "control" && decision !== "release") throw new FormatError("inconsistent", "controls must be released");
  return { id, label, proposes, expected: { decision, failing } };
}

/** All fixtures, attacks first (so controls' spending never decides an attack's outcome). */
export function loadFixtures(dir: string, a: Accounts): Fixture[] {
  const all = readdirSync(dir).filter((f) => f.endsWith(".json")).sort()
    .map((f) => parseFixture(readFileSync(join(dir, f), "utf8"), a));
  if (new Set(all.map((f) => f.id)).size !== all.length) throw new FormatError("schema", "duplicate fixture id");
  return [...all.filter((f) => f.label === "attack"), ...all.filter((f) => f.label === "control")];
}

/** The order the scripted agent submits for a fixture (canonical `sampan.order.v1`). */
export function orderFor(f: Fixture, mandateHash: string, orderId: string): string {
  return canonicalize({
    v: "sampan.order.v1", order_id: g.hex32(orderId, "order_id"), mandate_hash: g.hex32(mandateHash, "mandate_hash"),
    item: f.proposes.item, amount: f.proposes.amount, asset: f.proposes.asset, payee: f.proposes.payee,
  });
}
