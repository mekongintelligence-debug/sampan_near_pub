# apps/checker

A static receipt checker for a finance lead or any stranger: no wallet, no account, no Sampan
server. It reads a receipt (paste, file, or a link that carries the receipt after `#r=`) and
checks it against the NEAR blockchain through the RPC the viewer chooses.

```bash
node apps/checker/build.mjs     # writes apps/checker/dist/index.html (one file, works from disk)
pnpm exec vitest run apps/checker   # logic tests (recorded testnet answers) + browser tests
```

What it checks, each shown in plain language as Checked, Failed or Cannot verify:
1. The receipt file is complete and consistent (format, fingerprints, cross-references).
2. The buyer signed the mandate (NEP-413 or ERC-191).
3. The order stays inside what the buyer signed (payee, item, asset, budget).
4. The gate recorded this exact decision (`get_receipt`, final).
5. The decision transaction is final, executed by the gate, and carries this exact receipt.
6. The block height matches; for a release, the mandate had not expired.
7. The payee was paid (release), or no money moved (refusal).
8. Optional: a second RPC gives the same answers.

The page is green only if every check passes. Any RPC error, disagreement or non-final answer
shows "Cannot verify", never green. A strict Content-Security-Policy allows only the NEAR RPC
hosts listed in `src/rpc.ts`; everything is rendered with `textContent`.

The decision transaction is looked up with the agent, the refund account, the buyer's implicit
account and the gate as sender hints. Nothing is trusted from the hint: every check reads the
transaction itself. The testnet RPC ignores the hint (checked 7 Nov 2026), so a direct-checkout
decision sent by 1Click's account is found. **Assumption:** mainnet RPCs also ignore it. An RPC
that honoured it would need 1Click's own account, which the receipt does not name; the check then
shows "Cannot verify", never green (audit M7-09).
