#!/usr/bin/env node
// Posts an audit report to the team Telegram group for the security owner's sign-off.
// Usage: node scripts/post-audit.mjs <docs/audits/Mx.md> "<summary text>"
// Reads TG_TOKEN and TG_CHAT_ID from the environment. The token is part of the request URL,
// so no error message, log line or exception text ever includes the URL.
import { readFileSync } from "node:fs";
import { basename } from "node:path";

const [file, summary] = process.argv.slice(2);
const token = process.env.TG_TOKEN;
const chat = process.env.TG_CHAT_ID;
if (!file || !summary) { console.error("usage: node scripts/post-audit.mjs <report.md> \"<summary>\""); process.exit(2); }
if (!token || !chat) { console.error("TG_TOKEN and TG_CHAT_ID must be set in the environment"); process.exit(2); }

async function call(method, body) {
  let res;
  try {
    res = await fetch(`https://api.telegram.org/bot${token}/${method}`, { method: "POST", body });
  } catch {
    throw new Error(`Telegram ${method}: network error`); // never include the URL
  }
  const json = await res.json().catch(() => ({}));
  if (!json.ok) throw new Error(`Telegram ${method}: ${json.description ?? res.status}`);
  return json.result;
}

try {
  const msg = new FormData();
  msg.set("chat_id", chat);
  msg.set("text", summary);
  msg.set("disable_web_page_preview", "true");
  const sent = await call("sendMessage", msg);

  const doc = new FormData();
  doc.set("chat_id", chat);
  doc.set("reply_to_message_id", String(sent.message_id));
  doc.set("caption", `${basename(file)}: reply "signed off" or list issues`);
  doc.set("document", new Blob([readFileSync(file)], { type: "text/markdown" }), basename(file));
  await call("sendDocument", doc);
  console.log(`posted ${basename(file)} (message ${sent.message_id})`);
} catch (e) {
  console.error(String(e.message).replaceAll(token, "[redacted]"));
  process.exit(1);
}
