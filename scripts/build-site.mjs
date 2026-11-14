#!/usr/bin/env node
// Static public site for judges (M9; hosting is open question Q24): one folder that any static
// host can serve. It holds nothing secret and calls no server of ours.
//   node scripts/build-site.mjs [outDir]      (default: site/, git-ignored as build output)
//
//   index.html            short landing page: what it is, links to the shop, the checker and the receipts
//   shop/                 the test shop with the checkout widget in DRY mode (preview quote, never pays;
//                         live payments need the relayer and stay on testnet, audit M5-02)
//   checker/index.html    the receipt checker (single file, strict CSP)
//   examples/             the example receipts, to load in the checker
//   _headers              security headers for hosts that read this file (Netlify, Cloudflare Pages):
//                         frame-ancestors 'none' must come from a header, not a meta tag (audit M5-08)
import { cpSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { buildChecker } from "../apps/checker/build.mjs";
import { buildShop } from "../apps/test-shop/build.mjs";
import { buildExplainer } from "../apps/explainer/build.mjs";

const ROOT = resolve(import.meta.dirname, "..");
const out = resolve(process.argv[2] ?? resolve(ROOT, "site"));
// Only an empty folder or a previous site build (marked by .site-build) is replaced (M8-06).
const MARK = ".site-build";
if (existsSync(out) && readdirSync(out).length > 0 && !existsSync(resolve(out, MARK))) {
  console.error(`refusing to replace ${out}: it is not empty and not a previous site build`);
  process.exit(1);
}
rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
writeFileSync(resolve(out, MARK), "built by scripts/build-site.mjs\n");

await buildChecker(resolve(out, "checker/index.html"));
buildExplainer(resolve(out, "explainer/index.html"));
// The public shop is a DRY preview against mainnet USDC: 1Click quotes only real assets (it
// refuses the testnet mock token), and a dry quote never creates a deposit address. Recipient:
// the deployed mainnet gate once recorded, else the existing `near` account (as in the dry run).
// No relayer is named: a dry preview never registers anything (M8-07).
const gateFile = resolve(ROOT, "examples/mainnet-gate.json");
const mainnetGate = existsSync(gateFile) ? JSON.parse(readFileSync(gateFile, "utf8")).gate : "near";
await buildShop({ out: resolve(out, "shop"), mode: "dry", relayer: "", network: "mainnet", gate: mainnetGate, asset: "17208628f84f5d6ad33f0da3bbbeb27ffcb398eac501a31bd6ad2011e36133a1", payee: "shop.near" });
const receipts = [];
for (const net of ["mainnet", "testnet"]) {
  const dir = resolve(ROOT, "examples", net);
  if (!existsSync(dir)) continue;
  for (const f of readdirSync(dir).filter((x) => x.endsWith(".json") && !x.startsWith("mainnet-gate"))) {
    mkdirSync(resolve(out, "examples", net), { recursive: true });
    cpSync(resolve(dir, f), resolve(out, "examples", net, f));
    receipts.push(`${net}/${f}`);
  }
}

const css = "body{margin:0;background:#F6F2EA;color:#0C3B3D;font:17px/1.6 Inter,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif}main{max-width:46rem;margin:0 auto;padding:2.5rem 1.25rem 4rem}header{background:#0C3B3D;color:#F6F2EA;padding:3rem 1.25rem 3.5rem}header>div{max-width:46rem;margin:0 auto}.eyebrow{margin:0 0 .75rem;font-size:14px;font-weight:600;letter-spacing:2px;text-transform:uppercase;color:#F0A830}h1,h2{font-family:'Space Grotesk','Avenir Next','Segoe UI',system-ui,-apple-system,sans-serif;line-height:1.1}h1{margin:0 0 1rem;font-size:clamp(34px,6vw,56px);font-weight:700}h2{font-size:24px;margin:2.5rem 0 .75rem}.lede{margin:0;font-size:20px;color:#C9D8D3;max-width:38rem}a{color:#2F6DA8;text-underline-offset:3px}a:focus-visible{outline:3px solid #F0A830;outline-offset:2px}.cta{display:inline-block;margin:0 .75rem .75rem 0;padding:.8rem 1.4rem;border-radius:999px;background:#F0A830;color:#0C3B3D;font-weight:600;text-decoration:none}.cta.alt{background:transparent;color:#0C3B3D;border:2px solid #0C3B3D}code{font-size:.9em}li{margin:.35rem 0}@media (prefers-color-scheme:dark){body{background:#0A2F31;color:#F6F2EA}a{color:#8cc4cf}.cta.alt{color:#F6F2EA;border-color:#F6F2EA}}";
const sha = `'sha256-${createHash("sha256").update(css).digest("base64")}'`;
const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const list = receipts.map((r) => `<li><a href="examples/${esc(r)}" download>${esc(r)}</a></li>`).join("\n");
writeFileSync(resolve(out, "index.html"), `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${sha}; img-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<title>Sampan Trust checkout on NEAR</title><style>${css}</style></head>
<body>
<header><div>
<p class="eyebrow">Sampan Trust checkout on NEAR</p>
<h1>Pay only for what the buyer authorised.</h1>
<p class="lede">A checkout that can prove every payment was what the buyer authorised. A person or an AI agent pays from another chain through NEAR Intents, and anyone can check the receipt in the browser, with no wallet and no server of ours.</p>
</div></header>
<main>
<p><a class="cta" href="explainer/">Take the 1-minute tour</a><a class="cta alt" href="checker/">Open the receipt checker</a><a class="cta alt" href="shop/">Open the test shop</a></p>
<p>A NEAR contract pays the shop only for an order inside the buyer's signed mandate, and refuses the rest. The test shop is a dry checkout preview and never pays. Load one of the receipts below in the checker.</p>
<h2>Receipts</h2>
<ul>
${list}
</ul>
<p>On testnet the checker reads "Cannot verify" for two checks, because the test gate keeps an owner key. Every other check passes. Source code, claims and audits are in the repository README.</p>
</main>
</body></html>
`);
// One header list for both hosts: _headers (Cloudflare Pages, Netlify) and vercel.json (Vercel).
const SECURITY_HEADERS = {
  "Content-Security-Policy": "frame-ancestors 'none'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};
writeFileSync(resolve(out, "_headers"), `/*\n${Object.entries(SECURITY_HEADERS).map(([k, v]) => `  ${k}: ${v}`).join("\n")}\n`);
writeFileSync(
  resolve(out, "vercel.json"),
  JSON.stringify({ headers: [{ source: "/(.*)", headers: Object.entries(SECURITY_HEADERS).map(([key, value]) => ({ key, value })) }] }, null, 2) + "\n",
);
console.log(`built ${out}: index.html, explainer/, checker/, shop/ (dry), ${receipts.length} receipts, _headers, vercel.json`);
