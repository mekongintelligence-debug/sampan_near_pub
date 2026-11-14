#!/usr/bin/env node
// Builds the explainer tour into ONE static file (apps/explainer/dist/index.html): script and style
// are inlined and allowed by hash in a strict CSP. No network access at all (connect-src 'none'),
// nothing from a CDN, no images or fonts.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const here = import.meta.dirname;

export function buildExplainer(out = resolve(here, "dist/index.html")) {
  const js = readFileSync(resolve(here, "src/explainer.js"), "utf8");
  const css = readFileSync(resolve(here, "src/style.css"), "utf8");
  const sha = (s) => `'sha256-${createHash("sha256").update(s).digest("base64")}'`;
  const csp = [
    "default-src 'none'", `script-src ${sha(js)}`, `style-src ${sha(css)}`,
    "connect-src 'none'", "img-src 'none'", "font-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'none'",
  ].join("; ");
  const html = readFileSync(resolve(here, "src/index.html"), "utf8")
    .replace("__CSP__", csp).replace("<style>__STYLE__</style>", () => `<style>${css}</style>`).replace("<script>__SCRIPT__</script>", () => `<script>${js}</script>`);
  mkdirSync(resolve(out, ".."), { recursive: true });
  writeFileSync(out, html);
  return { out, bytes: html.length };
}

if (process.argv[1] === import.meta.filename) {
  const r = buildExplainer();
  console.log(`built ${r.out} (${r.bytes} bytes)`);
}
