# Cold test guide (for an outside tester)

Thank you for testing. We want to know whether a stranger can understand and check this project **from the README alone**. You need no wallet, no key and no money; nobody will ask you for one. About 45 minutes.

## Before you start
- **A computer** with macOS, Linux or Windows (with WSL).
- **Installed:** Node.js 22.18 or newer, and git. The README lists the rest.
- **Read access** to the repository; Jan sends you the link.
- **Keep a notes file open.** Write down every place where you hesitate, guess, or get stuck. Those notes are the result we want.

## What to do
1. Open the repository and read **only the README**. Do not open other files unless the README sends you there.
2. In your own words, write down the problem it solves, who it is for, and what NEAR does in it. Two or three sentences are enough.
3. Follow the README's **"Try it"** section exactly:
   ```bash
   git clone <link from Jan> && cd <folder>
   pnpm install
   pnpm dry-run
   ```
   Then open the receipt checker in your browser, as the README describes, and load one of the receipts in `examples/`.
4. Pick **two rows of the claim table** and try to check them yourself with the command or link given.
5. Optional, if you know Rust or TypeScript: run `make check`.

## What to note
For each step:
- did it work the first time?
- how long did it take?
- what did you see?
- was it what the README said you would see?

Also note:
- any word or sentence you did not understand;
- anything that felt like a claim without proof;
- the moment you would have given up, if any.

## Send back (copy and fill in)
```
Tester: ______   Date: ______   Computer/OS: ______   Time spent: ____ min

1. In my words, the project does: ______
2. "Try it": worked / partly / failed. Notes: ______
3. Receipt checker: what the page said: ______
4. Claim rows I checked, and the result: ______
5. Where I got stuck or confused: ______
6. Score, 1 to 10, for "a stranger can check the claims from the README alone": __
7. The one change that would help most: ______
```
Send it to Jan, by message or email. Your notes go into `docs/audits/M8-cold-test.md`, under your first name only, unless you prefer to stay anonymous.

## Good to know
- Some checks read **"Cannot verify"** on testnet. The README explains why; please say whether that explanation made sense to you.
- If a page takes a while (up to about 2 minutes for the dry run), that is expected.
- You cannot break anything: no step sends a transaction or spends money.
