import { describe, expect, it } from "vitest";

import {
  UnlockFailedError,
  changePassword,
  createAccount,
  unlockWithPassword,
  unlockWithRecoveryKey,
} from "../src/account/index.js";
import {
  LOGIN_CHALLENGE_CONTEXT,
  signChallenge,
  verifyChallenge,
  type Challenge,
} from "../src/challenge.js";
import { initCrypto } from "../src/init.js";

/** Avoid real HIBP in account crypto tests (fail-open empty range). */
const skipHibp = {
  passwordPolicy: {
    fetch: (async () =>
      new Response("", { status: 200 })) as typeof fetch,
  },
};

function expectSameBytes(a: Uint8Array, b: Uint8Array): void {
  expect(Buffer.from(a)).toEqual(Buffer.from(b));
}

describe("AMK-protected account identity", () => {
  it("createAccount identity signs a challenge that verifies", async () => {
    await initCrypto();
    const account = await createAccount("reg-password-1", skipHibp);

    const challenge: Challenge = {
      nonce: "Y2hhbGxlbmdl",
      issuedAt: 1_720_000_000_000,
      context: LOGIN_CHALLENGE_CONTEXT,
    };
    const signature = await signChallenge(
      account.identitySecretKeySeed,
      challenge,
    );
    expect(
      await verifyChallenge(account.identityPublicKey, challenge, signature),
    ).toBe(true);
  });

  it("password unlock recovers the same identity seed after discarding memory", async () => {
    await initCrypto();
    const created = await createAccount("unlock-password", skipHibp);
    const expectedSeed = Uint8Array.from(created.identitySecretKeySeed);
    const wrappedIdentityKey = created.wrappedIdentityKey;
    const passwordUnlock = created.passwordUnlock;

    created.amk.fill(0);
    created.identitySecretKeySeed.fill(0);
    created.recoveryKey.fill(0);

    const unlocked = await unlockWithPassword(
      wrappedIdentityKey,
      passwordUnlock,
      "unlock-password",
    );
    expectSameBytes(unlocked.identitySecretKeySeed, expectedSeed);
  });

  it("recovery-key unlock recovers the same identity seed", async () => {
    await initCrypto();
    const created = await createAccount("rk-password-01", skipHibp);
    const expectedSeed = Uint8Array.from(created.identitySecretKeySeed);
    const recoveryKey = Uint8Array.from(created.recoveryKey);

    created.amk.fill(0);
    created.identitySecretKeySeed.fill(0);

    const unlocked = await unlockWithRecoveryKey(
      created.wrappedIdentityKey,
      created.recoveryUnlock,
      recoveryKey,
    );
    expectSameBytes(unlocked.identitySecretKeySeed, expectedSeed);
  });

  it("wrong password / recovery key throw UnlockFailedError without leaking secrets", async () => {
    await initCrypto();
    const created = await createAccount("secret-password", skipHibp);

    await expect(
      unlockWithPassword(
        created.wrappedIdentityKey,
        created.passwordUnlock,
        "wrong-password",
      ),
    ).rejects.toBeInstanceOf(UnlockFailedError);

    try {
      await unlockWithRecoveryKey(
        created.wrappedIdentityKey,
        created.recoveryUnlock,
        new Uint8Array(32).fill(9),
      );
      expect.fail("expected UnlockFailedError");
    } catch (err) {
      expect(err).toBeInstanceOf(UnlockFailedError);
      expect(err).not.toHaveProperty("amk");
      expect(err).not.toHaveProperty("identitySecretKeySeed");
      expect(JSON.stringify(err)).not.toMatch(/amk|identitySecretKeySeed/i);
    }
  });

  it("changePassword issues a new wrap; old password fails against it", async () => {
    await initCrypto();
    const created = await createAccount("old-password", skipHibp);
    const newWrap = await changePassword(
      created.amk,
      "new-password",
      skipHibp.passwordPolicy,
    );

    expect(newWrap.ciphertext).not.toBe(created.passwordUnlock.ciphertext);
    expect(newWrap.nonce).not.toBe(created.passwordUnlock.nonce);

    const unlocked = await unlockWithPassword(
      created.wrappedIdentityKey,
      newWrap,
      "new-password",
    );
    expectSameBytes(unlocked.identitySecretKeySeed, created.identitySecretKeySeed);

    await expect(
      unlockWithPassword(
        created.wrappedIdentityKey,
        newWrap,
        "old-password",
      ),
    ).rejects.toBeInstanceOf(UnlockFailedError);

    const stillOld = await unlockWithPassword(
      created.wrappedIdentityKey,
      created.passwordUnlock,
      "old-password",
    );
    expectSameBytes(stillOld.identitySecretKeySeed, created.identitySecretKeySeed);
  });
});
