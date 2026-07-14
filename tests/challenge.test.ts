import { describe, expect, it } from "vitest";
import {
  LOGIN_CHALLENGE_CONTEXT,
  generateIdentityKeyPair,
  getLastUsageRecord,
  initCrypto,
  signChallenge,
  verifyChallenge,
  type Challenge,
} from "../src/index.js";

describe("challenge sign/verify", () => {
  it("round-trips a login challenge", async () => {
    await initCrypto();
    const id = await generateIdentityKeyPair();
    expect(id.secretKeySeed.length).toBe(32);
    expect(getLastUsageRecord()?.algorithm).toBe("ML-DSA-87");

    const challenge: Challenge = {
      nonce: "dGVzdC1ub25jZQ",
      issuedAt: 1_720_000_000_000,
      context: LOGIN_CHALLENGE_CONTEXT,
    };

    const signature = await signChallenge(id.secretKeySeed, challenge);
    expect(signature.length).toBeGreaterThan(0);
    expect(await verifyChallenge(id.publicKey, challenge, signature)).toBe(true);

    const other: Challenge = { ...challenge, nonce: "b3RoZXI" };
    expect(await verifyChallenge(id.publicKey, other, signature)).toBe(false);
  });
});
