import { describe, expect, it } from "vitest";
import {
  AEAD,
  PWHASH,
  generateSalt,
  labeledKdf32,
  pwhashDeriveKey,
} from "@enclave/pqc-primitives";

import {
  UnlockFailedError,
  WRAPPED_AMK_FORMAT_VERSION,
  decodeRecoveryKeyFromDisplay,
  encodeRecoveryKeyForDisplay,
  generateAmk,
  generateRecoveryKey,
  registerPasswordMethod,
  registerPinMethod,
  registerRecoveryKeyMethod,
  unlockWithPassword,
  unlockWithPin,
  unlockWithRecoveryKey,
  wrapAmk,
  type WrappedAmk,
} from "../src/amk/index.js";
import { bytesToBase64Url, utf8Encode } from "../src/encoding.js";
import { initCrypto } from "../src/init.js";

function expectSameBytes(a: Uint8Array, b: Uint8Array): void {
  expect(Buffer.from(a)).toEqual(Buffer.from(b));
}

describe("AMK unlock methods", () => {
  it("password method round-trips", async () => {
    await initCrypto();
    const amk = generateAmk();
    expect(amk.length).toBe(AEAD.KEY_BYTES);

    const wrapped = await registerPasswordMethod(amk, "correct horse battery");
    expect(wrapped.method).toBe("password");
    expect(wrapped.formatVersion).toBe(WRAPPED_AMK_FORMAT_VERSION);
    expect(wrapped.salt).toBeTruthy();
    expect(wrapped.argon2Params).toEqual({
      memoryCostKib: PWHASH.RECOMMENDED_PARAMS.memoryCostKib,
      iterations: PWHASH.RECOMMENDED_PARAMS.iterations,
      parallelism: PWHASH.RECOMMENDED_PARAMS.parallelism,
    });

    const unlocked = await unlockWithPassword(wrapped, "correct horse battery");
    expectSameBytes(unlocked, amk);
  });

  it("recovery-key method round-trips", async () => {
    await initCrypto();
    const amk = generateAmk();
    const recoveryKey = generateRecoveryKey();
    const wrapped = await registerRecoveryKeyMethod(amk, recoveryKey);
    expect(wrapped.method).toBe("recovery-key");
    expect(wrapped.salt).toBeUndefined();
    expect(wrapped.argon2Params).toBeUndefined();

    const unlocked = await unlockWithRecoveryKey(wrapped, recoveryKey);
    expectSameBytes(unlocked, amk);
  });

  it("three methods wrap the same AMK independently", async () => {
    await initCrypto();
    const amk = generateAmk();
    const password = "shared-amk-password";
    const recoveryKey = generateRecoveryKey();

    const pwWrap = await registerPasswordMethod(amk, password);
    const rkWrap = await registerRecoveryKeyMethod(amk, recoveryKey);
    const { pinUnlock } = await registerPinMethod(amk, "SharedPin1");

    expectSameBytes(await unlockWithPassword(pwWrap, password), amk);
    expectSameBytes(await unlockWithRecoveryKey(rkWrap, recoveryKey), amk);
    expectSameBytes(await unlockWithPin(pinUnlock, "SharedPin1"), amk);

    await expect(unlockWithPassword(rkWrap, password)).rejects.toBeInstanceOf(
      UnlockFailedError,
    );
    await expect(
      unlockWithRecoveryKey(pinUnlock, recoveryKey),
    ).rejects.toBeInstanceOf(UnlockFailedError);
    await expect(unlockWithPin(pwWrap, "SharedPin1")).rejects.toBeInstanceOf(
      UnlockFailedError,
    );

    await expect(
      unlockWithPassword(pwWrap, "not-the-password"),
    ).rejects.toBeInstanceOf(UnlockFailedError);
    await expect(
      unlockWithRecoveryKey(rkWrap, generateRecoveryKey()),
    ).rejects.toBeInstanceOf(UnlockFailedError);
    await expect(unlockWithPin(pinUnlock, "WrongPin9")).rejects.toBeInstanceOf(
      UnlockFailedError,
    );
  });

  it("wrong secrets never leak raw primitives errors", async () => {
    await initCrypto();
    const amk = generateAmk();
    const wrapped = await registerPasswordMethod(amk, "secret");

    try {
      await unlockWithPassword(wrapped, "wrong");
      expect.fail("expected UnlockFailedError");
    } catch (err) {
      expect(err).toBeInstanceOf(UnlockFailedError);
      expect((err as Error).name).toBe("UnlockFailedError");
      expect(String(err)).not.toMatch(/AeadFailure/i);
    }
  });

  it("recovery key BIP39 encode/decode round-trips", () => {
    const key = generateRecoveryKey();
    const display = encodeRecoveryKeyForDisplay(key);
    const words = display.split(" ");
    expect(words).toHaveLength(24);
    expectSameBytes(decodeRecoveryKeyFromDisplay(display), key);

    const messy = display.toUpperCase().split(" ").join("  \n ");
    expectSameBytes(decodeRecoveryKeyFromDisplay(messy), key);
  });

  it("matches BIP39 all-zero entropy vector (24 words)", () => {
    const entropy = new Uint8Array(32);
    const mnemonic = encodeRecoveryKeyForDisplay(entropy);
    expect(mnemonic).toBe(
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
    );
    expectSameBytes(decodeRecoveryKeyFromDisplay(mnemonic), entropy);
  });

  it("password unlock uses stored params, not current recommended", async () => {
    await initCrypto();
    const amk = generateAmk();
    const storedParams = {
      memoryCostKib: 7168,
      iterations: 5,
      parallelism: 1,
    };
    const salt = generateSalt();
    const derived = pwhashDeriveKey(
      utf8Encode("params-freeze-test"),
      salt,
      storedParams,
    );
    const parts = wrapAmk(amk, derived);
    const wrapped: WrappedAmk = {
      formatVersion: WRAPPED_AMK_FORMAT_VERSION,
      method: "password",
      nonce: parts.nonce,
      ciphertext: parts.ciphertext,
      salt: bytesToBase64Url(salt),
      argon2Params: storedParams,
    };

    expect(storedParams).not.toEqual({
      memoryCostKib: PWHASH.RECOMMENDED_PARAMS.memoryCostKib,
      iterations: PWHASH.RECOMMENDED_PARAMS.iterations,
      parallelism: PWHASH.RECOMMENDED_PARAMS.parallelism,
    });

    const unlocked = await unlockWithPassword(wrapped, "params-freeze-test");
    expectSameBytes(unlocked, amk);

    const rk = generateRecoveryKey();
    const a = labeledKdf32("enclave-auth:amk-recovery-key:v1", rk);
    const b = labeledKdf32("enclave-auth:pin-wrap:v1", rk);
    expect(Buffer.from(a)).not.toEqual(Buffer.from(b));
  });
});
