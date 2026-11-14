// M4-CR3: the agent process gets an allow-listed environment with no credentials.
import { describe, it, expect } from "vitest";
import { agentEnv } from "./agent-env.mjs";

describe("agent environment", () => {
  it("passes only the allow-list and never a credential", () => {
    const env = agentEnv({ PATH: "/bin", HOME: "/h", HTTPS_PROXY: "http://p", NEAR_TESTNET_PRIVATE_KEY: "ed25519:x", TG_TOKEN: "t", GH_TOKEN: "g", AWS_SECRET_ACCESS_KEY: "a", NEAR_TESTNET_ACCOUNT_ID: "x.testnet" });
    expect(Object.keys(env).sort()).toEqual(["HTTPS_PROXY", "PATH"]);
  });
});
