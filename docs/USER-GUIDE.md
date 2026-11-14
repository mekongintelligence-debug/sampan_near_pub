# User guide: Sampan Trust checkout

**What it is.** A checkout that can prove every payment was what the buyer authorised. A buyer pays from another chain through NEAR Intents (1Click). A NEAR contract, the *gate*, holds the money and pays the shop only for an order inside the buyer's signed *mandate*. Every release, and every refusal of an authenticated order by the rules R1 to R9, leaves a *receipt* that anyone can check in a browser (section 7 lists the refusals that leave only an event).

**Who this guide is for**
1. [Buyers paying directly](#1-buyers-paying-directly)
2. [Buyers who let an AI agent buy for them](#2-buyers-who-let-an-ai-agent-buy-for-them)
3. [Shops (sellers)](#3-shops-sellers)
4. [Agent operators](#4-agent-operators)
5. [Finance leads, auditors and anyone checking a receipt](#5-finance-leads-auditors-and-anyone-checking-a-receipt)
6. [The operators behind the scenes: the relayer and the guardian](#6-the-operators-behind-the-scenes)
7. [Limits, and what to do when something goes wrong](#7-limits-and-what-to-do-when-something-goes-wrong)

**Status (November 2026).** This is a hackathon prototype.
- **Testnet:** the full flow works with a test token. No real money is involved.
- **Mainnet:** the gate and the first purchases are run by the team with person-run scripts.
- **The checkout widget** takes live payments on **testnet only**, until it runs in an isolated checkout frame (see section 7). On mainnet it shows a preview that never takes a payment.

**Words used here**

| Word | Meaning |
|---|---|
| Mandate | What the buyer signs: who gets paid (payee), which items, the price or budget, the token, an expiry time, where refunds go, and optionally which AI agent may buy. |
| Gate | The NEAR contract that holds the payment and decides each order by fixed rules (R1 to R9). No AI model decides. |
| Order | One purchase under a mandate: item, amount, payee. |
| Receipt | A file describing one decision (release or refusal), anchored on NEAR so anyone can check it. |
| Refund due | Money the gate owes back to the buyer, for example an overpayment. Anyone can trigger its refund at any time, and it goes only to the buyer's refund account. |

---

## 1. Buyers paying directly

**You need**
- An EVM wallet, for example MetaMask, holding USDC on Base and a little ETH on Base for gas.
- A NEAR refund account. This is your own wallet address used as a NEAR account (an Ethereum-style implicit account, `0x…` in lower case). If it does not exist yet, the checkout tells you, and you create it by receiving a small amount of NEAR. **Assumption:** this behaves as NEAR documents for refunds; the team checks it with the first mainnet purchase.

**Steps**
1. **On the shop's page, press the checkout button.** Your wallet asks to connect. That only shares your address; nothing is signed yet.
2. **Read what the checkout shows before you sign:**
   - the item and the exact price, to 6 decimals;
   - who gets paid (the payee);
   - the gate's account and network;
   - where refunds go, both on NEAR and on Base;
   - when the offer ends;
   - the mandate's ID (a long hex string, the mandate hash).

   If anything looks wrong, stop. Signing is the moment you authorise the payment.
3. **Sign.** Your wallet shows a text message, the mandate. Signing it costs nothing and moves no money.
4. **The checkout registers your mandate on the gate**, using Sampan's relayer, which pays a refundable storage deposit. It then confirms with the gate itself that the gate holds exactly your mandate.
5. **The checkout shows a deposit address, the exact amount to send, a deadline, and your mandate's ID again.** Check that the ID matches step 2. Send exactly that amount from your wallet on Base, before the deadline.
6. **Done.** 1Click delivers the USDC to the gate on NEAR, usually within a minute. The gate checks the order against your mandate and pays the shop exactly the signed price, once.
7. **Keep your receipt.** The checkout offers "Save the payment record"; keep that file. The shop or the checker can show your receipt from chain data at any time.

**If something goes wrong**
- **Your payment never reached the gate** (for example, you paid after the deadline). 1Click refunds to your address on Base.
- **The payment reached the gate but could not be used** (overpaid, too late, the order did not match). The money becomes "refund due" and goes to your NEAR refund account. Anyone can trigger that refund, at any time.
- **The shop could not be paid** (rare: a token problem on the shop's side). The money becomes refund due as well.

---

## 2. Buyers who let an AI agent buy for them

You sign a mandate that names an agent account, a list of items, one payee and a total budget. The agent can then buy only within that mandate.

1. **Sign a mandate naming the agent.** Fund it with the budget (up to the gate's limits); the money waits in the gate.
2. **The agent buys by sending orders to the gate.** Its key can call the gate's `purchase` and nothing else: NEAR itself refuses any other action with that key, such as a transfer, another contract or another method.
3. **The gate releases only an order that fits:** a listed item, the signed payee, within the remaining budget, before expiry. An order that breaks one of these rules is refused, and the refusal is recorded as a receipt you can check. A few refusals leave only an event (section 7).
4. **When the mandate expires,** anything left goes back to your refund account. Anyone can trigger that refund.

**What this protects you from.** An agent tricked by a web page into paying someone else, buying an unlisted item, or spending above the budget is refused. In the project's attack suite, 6 of 6 such attempts were refused, with no false refusals of valid orders.

**What it does not protect you from.** The gate enforces what you signed, not what you meant. If you list two items and a budget, a tricked agent can still buy the other listed item, or pay a surcharge within the budget. Sign narrow mandates.

---

## 3. Shops (sellers)

**What you get.** Payments from buyers on other chains, settled in USDC on NEAR, each with a receipt your customer and your finance team can check without trusting you or Sampan.

**Getting started**
1. **A NEAR account for payouts**, for example `yourshop.near`. The gate registers it with the USDC token on first payout if needed.
2. **Ask Sampan to list your account** on the relayer. The relayer only pays registration deposits for mandates whose payee is a listed shop, and only up to its price limit.
3. **Add the checkout to your page:**
   ```html
   <div id="sampan-checkout"></div>
   <script src="sampan-checkout.js" integrity="sha384-…" crossorigin="anonymous"
     data-network="testnet" data-gate="<gate account>" data-asset="<token>"
     data-payee="yourshop.near" data-item="<item id>" data-label="<what the buyer sees>"
     data-price="<price in USDC base units, 6 decimals>" data-relayer="<relayer URL>" data-mode="live"></script>
   ```
   Always use the `integrity` hash published with the release. The browser refuses a changed script.
   **Live payments work on testnet only** for now. With `data-network="mainnet"`, the widget refuses `data-mode="live"` and offers only `data-mode="dry"`, a preview that never takes a payment, until it runs in an isolated checkout frame (section 7).
4. **Security headers.** Serve your page with `Content-Security-Policy: frame-ancestors 'none'`, and allow only the hosts the checkout needs in `connect-src`: 1Click, the NEAR RPC, and the relayer. The test shop (`apps/test-shop/build.mjs`) shows a working policy.

**Your responsibilities**
- **Your page is part of the trust.** A script on your page, such as a compromised analytics tag or dependency, can change what the checkout shows, including the deposit address. Keep third-party scripts off the checkout page. This is why live mainnet payments wait for the isolated checkout frame (section 7).
- **The price and the payee you put in the page are what the buyer signs.** Check them.

**After a sale**
- The gate pays the exact signed price to your payout account, once per order.
- Each sale has a receipt: send it to your customer with the order, or let them check it in the checker.

---

## 4. Agent operators

You run the software, the "agent", that buys for a buyer.

1. **Give the agent its own NEAR account** and a **function-call key** for the gate only: receiver = the gate, method `purchase`, a small allowance (0.25 NEAR covers many purchases). Never give it a full-access key.
2. **Keep the key away from the model's text.** The demo (`apps/agent-demo`) runs the agent as a separate system user, with only the variables it needs.
3. **The agent sends an order** (`sampan.order.v1`: order ID, mandate hash, item, amount, token, payee) to the gate's `purchase`. The answer is `release` (paid) or `refuse` with the failed rules. A release and a refusal by the rules R1 to R9 are anchored as receipts. A repeated order ID, an unfunded mandate, the 16-order cap, too little gas, a malformed order or a stopped gate are refused with only an event.
4. **Use a new order ID every time.** A repeated ID is refused without a receipt, so a replay cannot overwrite one.
5. **Delete the function-call key** when the job is done.

---

## 5. Finance leads, auditors and anyone checking a receipt

You need nothing but a browser: no wallet, no account, and no Sampan server.

1. **Open the checker page.** Use the hosted page, or open the single file `apps/checker/dist/index.html` from disk. It works offline except for its questions to NEAR.
2. **Load the receipt**: paste it, choose the file, or open a receipt link. The check starts by itself and takes up to about 30 seconds.
3. **Read the verdict and each check**:
   - the receipt file is complete and consistent;
   - the buyer signed this mandate;
   - the order stays inside what was signed (for a refusal: which rule it broke, in plain words);
   - the gate is a known gate running reviewed code, and nobody can change it;
   - the gate recorded this exact decision, in a final transaction, at the stated block;
   - for a release: the payee was paid, and the deposit and payout transactions are on chain.
4. **Verdicts:**
   - **"Verified"**: every check passed against the chain.
   - **"Not valid"**: something in the file contradicts the chain. Do not accept it.
   - **"Cannot verify"**: a check could not be completed (the network did not answer, or, on the test network, the test gate still has an owner key). This is never shown as green.
5. **Make it stronger:**
   - **Add a second NEAR RPC, run by someone else.** The page re-runs every check there, and the answers must agree.
   - **Use the archival RPC for older receipts** (`archival-rpc.mainnet.near.org` or `archival-rpc.testnet.near.org`). Regular RPCs forget transactions after about a day.

**What the checker relies on.** The NEAR RPC you choose, and the list of known gates built into the checker. It never trusts the note attached to a receipt; that is shown as untrusted text.

---

## 6. The operators behind the scenes

- **Sampan's relayer**
  - **What it does:** registers buyers' signed mandates on the gate and pays the refundable storage deposit, about 0.0985 NEAR per mandate. It gets the deposit back, minus what the mandate leaves on chain, when the mandate closes, and it closes expired mandates itself.
  - **What it cannot do:** sign or change a mandate, or move tokens.
  - **Its limits:** listed shops only, a price cap, the checkout's own 2-hour lifetime, and at most 2 open registrations per client.
- **The guardian**
  - **What it does:** a named person, holding a hardware wallet, who can **stop** the gate once and for good if a serious problem is found. After a stop, no new mandates or purchases are accepted, refunds keep working, and money already in the gate stays refundable to buyers.
  - **What it cannot do:** move funds, and the stop cannot be undone.
- **The gate itself** is to be locked after deployment: all its keys are deleted, so nobody, including Sampan, can change its code or rules. The checker shows whether a gate is locked ("Nobody can change the gate"). Its limits are fixed at deployment, for example at most 50 USDC held for open purchases on the first mainnet gate.
- **1Click (NEAR Intents)** quotes and delivers the cross-chain payment. If it cannot deliver, it refunds the buyer on the original chain. Its quote signature is not yet verified by the checkout (stated limit).

---

## 7. Limits, and what to do when something goes wrong

**Stated limits**
- **The gate enforces what was signed, not what was meant.** A buyer misled into signing a wrong payee will see that payee paid.
- **The checkout runs inside the shop's page,** so a hostile script on that page can change what it shows. Live widget payments therefore stay on testnet until the checkout runs in an isolated frame hosted by Sampan. On mainnet the widget shows a preview only.
- **Some refusals leave only an event, not a stored receipt:** a refused order sent inside a payment (the payment is owed back to the buyer at once), and, for any caller, a repeated order ID, an unfunded mandate (no escrow), the 16-order cap per mandate, too little gas, a malformed order, and any order after the gate is stopped. Refusals of an authenticated order by the rules R1 to R9 are anchored as receipts.
- **The gate's capacity can be held:** anyone can fill all open-mandate slots, or the total-escrow cap, for up to 24 hours with their own refundable deposits and money. New checkouts are then refused until those mandates expire; no money is lost (audit A1R-03).
- **Tokens sent to the gate with a plain transfer,** without a payment message, are never credited and cannot be recovered. The same holds for NEAR sent to the gate. Only pay through the checkout.
- **The token contract is trusted.** Its issuer can freeze accounts, which would hold payouts and refunds until the issuer acts.
- **The checker trusts the NEAR RPC it asks.** Use a second, independent RPC to cross-check.

**When something goes wrong**

| Situation | What happens | What you do |
|---|---|---|
| Paid after the deadline, or 1Click could not deliver | 1Click refunds on the original chain | Wait for the refund; keep the payment record |
| Overpaid, or the order did not fit | The extra becomes "refund due" | Anyone can trigger the refund to your NEAR refund account |
| The shop could not be paid | The money becomes refund due | As above |
| The mandate expired with money left | The money stays refundable | Anyone can trigger the refund after expiry |
| A receipt reads "Not valid" | The file contradicts the chain | Do not accept it; ask the sender for the original |
| A serious bug is found | The guardian may stop the gate | Refunds keep working; follow the team's announcement |

**Further reading:** the formats in `docs/FORMATS.md`, the security plan and threat model in `docs/SECURITY.md`, the audits in `docs/audits/`, and the disclosures in `HACKATHON.md`.
