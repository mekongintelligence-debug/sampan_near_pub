#!/usr/bin/env node
// Builds the checker into ONE static file, apps/checker/dist/index.html, that works when
// opened from disk. Script and style are inlined and allowed by hash in a strict CSP; the
// page may connect only to the allowed NEAR RPC hosts. Nothing is loaded from a CDN.
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { ALLOWED_RPC_HOSTS as hosts } from "./src/rpc.ts"; // one list for the code and the CSP

const here = import.meta.dirname;

export async function buildChecker(out = resolve(here, "dist/index.html")) {
  const js = (await build({ entryPoints: [resolve(here, "src/ui.ts")], bundle: true, write: false, format: "iife", target: "es2022", minify: true, legalComments: "none" })).outputFiles[0].text.replace(/<\/script/gi, "<\\/script");
  const css = readFileSync(resolve(here, "src/style.css"), "utf8");
  const sha = (s) => `'sha256-${createHash("sha256").update(s).digest("base64")}'`;
  const csp = [
    "default-src 'none'", `script-src ${sha(js)}`, `style-src ${sha(css)}`,
    `connect-src ${hosts.map((h) => `https://${h}`).join(" ")}`,
    "img-src 'none'", "font-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'none'",
  ].join("; ");
  const html = readFileSync(resolve(here, "src/index.html"), "utf8")
    .replace("__CSP__", csp).replace("<style>__STYLE__</style>", () => `<style>${css}</style>`).replace("<script>__SCRIPT__</script>", () => `<script>${js}</script>`);
  mkdirSync(resolve(out, ".."), { recursive: true });
  writeFileSync(out, html);
  return { out, hosts, bytes: html.length };
}

if (process.argv[1] === import.meta.filename) {
  const r = await buildChecker();
  console.log(`built ${r.out} (${r.bytes} bytes)`);
}
