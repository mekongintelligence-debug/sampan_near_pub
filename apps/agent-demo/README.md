# apps/agent-demo

Scripted agent for the M4 demo (no model). It reads the labelled product pages in
`fixtures/attacks/agent-demo/`, submits what each page talks it into, and shows that the gate
refuses every injected order while valid orders are released. A second mode tries every action
the agent's key must not be able to do. Results: `docs/m4-testnet.md`.

The agent process holds only a function-call key for `gate.purchase`. It refuses to start if it
can see the operator's secrets, and checks its key on chain before acting.

```bash
pnpm demo:setup      # operator: agent key + funded mandate (testnet)
pnpm demo:attack     # agent: the labelled injection suite
pnpm demo:direct     # agent: forbidden actions with the same key
pnpm demo:edge       # operator: allowance exhausted, key removed mid-demo
pnpm demo:teardown   # operator: delete the agent's function-call keys
```
