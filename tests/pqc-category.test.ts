import { describe, expect, it } from "vitest";

import {
  encodePublicKey,
  generateIdentityKeyPair,
  initCrypto,
  signChallenge,
  verifyChallenge,
  LOGIN_CHALLENGE_CONTEXT,
  type Challenge,
} from "../src/index.js";

const challenge: Challenge = {
  nonce: "dGVzdC1ub25jZQ",
  issuedAt: 1_700_000_000_000,
  context: LOGIN_CHALLENGE_CONTEXT,
};

describe("pqc category identity + challenge", () => {
  it("cat5 roundtrip unchanged", async () => {
    await initCrypto();
    const kp = await generateIdentityKeyPair("cat5");
    const sig = await signChallenge(kp.secretKeySeed, challenge, "cat5");
    expect(
      await verifyChallenge(kp.publicKey, challenge, sig, "cat5"),
    ).toBe(true);
    await expect(
      verifyChallenge(kp.publicKey, challenge, sig, "cat3"),
    ).rejects.toThrow(/publicKey must be/);
  });

  it("cat3 uses ML-DSA-65 sizes", async () => {
    await initCrypto();
    const kp = await generateIdentityKeyPair("cat3");
    const b64 = encodePublicKey(kp.publicKey, "cat3");
    expect(kp.publicKey.length).toBe(1952);
    expect(b64.length).toBeGreaterThan(0);
    const sig = await signChallenge(kp.secretKeySeed, challenge, "cat3");
    expect(await verifyChallenge(kp.publicKey, challenge, sig, "cat3")).toBe(
      true,
    );
  });
});
