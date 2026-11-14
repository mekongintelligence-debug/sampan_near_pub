# examples

Receipt envelopes rebuilt from chain data only (`packages/receipt/src/pack.ts`, `pnpm e2e`). Check them with `pnpm dry-run` or by loading them in the checker page (`node apps/checker/build.mjs`, then open `apps/checker/dist/index.html`).

## testnet/ (test token, no real money)
- `direct-checkout-release.json`: a person's direct checkout. The payment carried `{"mandate_hash","order"}` (the 1Click form), and the gate released and paid the shop in the same transaction.
- `agent-release.json`: an AI agent's function-call key bought `report-001` within the signed mandate.
- `agent-refusal.json`: the agent tried to pay another payee. The gate refused (rule R8) and anchored the refusal; no money moved.

On testnet the checker reads "Cannot verify" for two checks ("Nobody can change the gate" and "The gate ran reviewed code when it decided"), because the test gate keeps an owner key (decision Q16). Every other check passes.

## mainnet/
Added after the person-run mainnet deploy and first purchase.
