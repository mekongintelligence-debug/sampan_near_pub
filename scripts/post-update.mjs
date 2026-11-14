#!/usr/bin/env node
// Posts a development update (Markdown-free plain text file) to the team Telegram group.
// Usage: node scripts/post-update.mjs <file.txt>
// Reads TG_TOKEN and TG_CHAT_ID; never prints the token or the request URL.
import { readFileSync } from "node:fs";

const file = process.argv[2];
const token = process.env.TG_TOKEN;
const chat = process.env.TG_CHAT_ID;
if (!file) { console.error("usage: node scripts/post-update.mjs <file.txt>"); process.exit(2); }
if (!token || !chat) { console.error("TG_TOKEN and TG_CHAT_ID must be set in the environment"); process.exit(2); }

// Telegram allows 4096 characters per message: split on blank lines.
const parts = [];
for (const block of readFileSync(file, "utf8").trim().split(/\n\s*\n/)) {
  const last = parts.at(-1);
  if (last !== undefined && last.length + block.length + 2 <= 3900) parts[parts.length - 1] = `${last}\n\n${block}`;
  else parts.push(block.slice(0, 3900));
}
try {
  for (const text of parts) {
    let res;
    try {
      res = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ chat_id: chat, text, disable_web_page_preview: true }),
      });
    } catch { throw new Error("Telegram sendMessage: network error"); }
    const j = await res.json().catch(() => ({}));
    if (!j.ok) throw new Error(`Telegram sendMessage: ${j.description ?? res.status}`);
  }
  console.log(`posted ${parts.length} message(s)`);
} catch (e) {
  console.error(String(e.message).replaceAll(token, "[redacted]"));
  process.exit(1);
}
