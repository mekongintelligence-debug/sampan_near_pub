#!/usr/bin/env node
// Builds the checkout widget into one file and the test shop page that loads it with
// Subresource Integrity (sha384) under a strict CSP. Nothing is loaded from a CDN.
//   node apps/test-shop/build.mjs [--mode dry|live]
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { WIDGET_CSS } from "../checkout-widget/src/style.ts";
import { ONECLICK_API, NEAR_RPC } from "../../packages/payments/src/index.ts";

const here = import.meta.dirname;
export const SHOP = {
  network: "testnet", gate: "gate-m3.sampan-trust-01.testnet", asset: "token.sampan-trust-01.testnet",
  payee: "payee2-m3.sampan-trust-01.testnet", item: "report-002", label: "One-page market report (test)", price: "1000000",
  relayer: "http://127.0.0.1:8790",
};

export async function buildShop({ out = resolve(here, "dist"), mode = "dry", integrity, relayer = SHOP.relayer, network = SHOP.network, gate = SHOP.gate, asset = SHOP.asset, payee = SHOP.payee } = {}) {
  const js = (await build({ entryPoints: [resolve(here, "../checkout-widget/src/widget.ts")], bundle: true, write: false, format: "iife", target: "es2022", minify: true, legalComments: "none" })).outputFiles[0].text;
  const sri = `sha384-${createHash("sha384").update(js).digest("base64")}`;
  const sha256 = (s) => `'sha256-${createHash("sha256").update(s).digest("base64")}'`;
  const shopCss = "body{font:16px/1.55 Inter,system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;margin:0;background:#F6F2EA;color:#0C3B3D}body>*{max-width:40rem;margin-left:auto;margin-right:auto;padding:0 1rem}h1{font-family:'Space Grotesk','Avenir Next','Segoe UI',system-ui,-apple-system,sans-serif;font-weight:700;font-size:clamp(28px,5vw,40px);line-height:1.1;margin-top:2rem}";
  const csp = [
    "default-src 'none'", "script-src 'self'", `style-src ${sha256(WIDGET_CSS)} ${sha256(shopCss)}`,
    // frame-ancestors is ignored in a meta CSP (M5-08): serve the page with that header.
    `connect-src ${[new URL(ONECLICK_API).origin, new URL(NEAR_RPC[network]).origin, relayer].filter(Boolean).join(" ")}`, "img-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'none'",
  ].join("; ");
  const attrs = Object.entries({ ...SHOP, network, gate, asset, payee, relayer, mode }).filter(([, v]) => v !== "").map(([k, v]) => ` data-${k}="${v}"`).join("");
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${csp}">
<title>Test shop</title><style>${shopCss}</style></head>
<body><h1>Test shop</h1><p>${SHOP.label}: ${(Number(SHOP.price) / 1e6).toFixed(2)} ${network === "testnet" ? "test USDC. Testnet, no real money." : "USDC. Preview only: this page never creates a deposit address and cannot take a payment."}</p>
<div id="sampan-checkout"></div>
<script src="sampan-checkout.js" integrity="${integrity ?? sri}" crossorigin="anonymous"${attrs}></script>
</body></html>
`;
  mkdirSync(out, { recursive: true });
  writeFileSync(resolve(out, "sampan-checkout.js"), js);
  writeFileSync(resolve(out, "index.html"), html);
  return { out, sri, csp };
}

if (process.argv[1] === import.meta.filename) {
  const i = process.argv.indexOf("--mode");
  const r = await buildShop({ mode: i > 0 ? process.argv[i + 1] : "dry" });
  console.log(`built ${r.out} (widget ${r.sri})`);
}
