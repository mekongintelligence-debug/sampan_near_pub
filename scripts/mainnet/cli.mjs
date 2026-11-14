// Shared helpers for the person-run mainnet scripts (deploy-gate.mjs, mainnet-proof/proof.mjs).
export function args(argv) {
  const out = { cmd: argv[0] };
  for (let i = 1; i < argv.length; i += 2) out[argv[i].replace(/^--/, "")] = argv[i + 1];
  return out;
}
export function stop(problems) {
  if (problems.length) { console.error("STOP:\n- " + problems.join("\n- ")); process.exit(1); }
}
/** Ask at the terminal; `hidden` echoes nothing typed (for a secret key). */
export async function ask(question, { hidden = false } = {}) {
  const { createInterface } = await import("node:readline");
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  if (hidden) rl._writeToOutput = (s) => { if (s.includes(question)) process.stdout.write(question); };
  const answer = await new Promise((r) => rl.question(question, r));
  rl.close();
  if (hidden) process.stdout.write("\n");
  return answer.trim();
}
/** Stop unless a person runs this at an interactive terminal, with no key in the environment. */
export function requirePerson() {
  if (!process.stdin.isTTY || process.env.CI || process.env.CLAUDECODE || process.env.CLAUDE_CODE_REMOTE) stop(["this script is for a person at an interactive terminal"]);
  for (const k of Object.keys(process.env)) if (/PRIVATE_KEY|SECRET_KEY|SEED_PHRASE/i.test(k)) stop([`unset ${k}: this script takes keys only from the prompt`]);
}
