import { describe, expect, it } from "vitest";
import { AEAD, PWHASH } from "@enclave/pqc-primitives";

import {
  PIN_VERIFY_KDF_LABEL,
  PIN_WRAP_KDF_LABEL,
  UnlockFailedError,
  WRAPPED_AMK_FORMAT_VERSION,
  derivePinMaterial,
  generateAmk,
  registerPinMethod,
  unlockWithPin,
  unwrapAmk,
  verifyPin,
} from "../src/amk/index.js";
import { base64UrlToBytes } from "../src/encoding.js";
import { initCrypto } from "../src/init.js";
import {
  PIN_MIN_LENGTH,
  PinPolicyError,
  validatePin,
} from "../src/pin-policy.js";
import {
  createAccount,
  setPinMethod,
  unlockWithPin as unlockAccountWithPin,
} from "../src/account/index.js";

function expectSameBytes(a: Uint8Array, b: Uint8Array): void {
  expect(Buffer.from(a)).toEqual(Buffer.from(b));
}

const skipHibp = {
  passwordPolicy: {
    fetch: (async () =>
      new Response("", { status: 200 })) as typeof fetch,
  },
};

describe("pin policy", () => {
  it("rejects short and trivial PINs", () => {
    expect(validatePin("short")).toEqual({
      valid: false,
      reason: "too_short",
    });
    expect(validatePin("a".repeat(PIN_MIN_LENGTH))).toEqual({
      valid: false,
      reason: "trivial_pattern",
    });
    expect(validatePin("12345678")).toEqual({
      valid: false,
      reason: "trivial_pattern",
    });
    expect(validatePin("abcdefgh")).toEqual({
      valid: false,
      reason: "trivial_pattern",
    });
    expect(validatePin("MyRecov1")).toEqual({ valid: true });
  });
});

describe("PIN unlock method", () => {
  it("register + verify + unlock round-trips", async () => {
    await initCrypto();
    const amk = generateAmk();
    expect(amk.length).toBe(AEAD.KEY_BYTES);

    const { verificationHash, pinUnlock } = await registerPinMethod(
      amk,
      "MyRecov1",
    );
    expect(pinUnlock.method).toBe("pin");
    expect(pinUnlock.formatVersion).toBe(WRAPPED_AMK_FORMAT_VERSION);
    expect(verificationHash.argon2Params).toEqual({
      memoryCostKib: PWHASH.RECOMMENDED_PARAMS.memoryCostKib,
      iterations: PWHASH.RECOMMENDED_PARAMS.iterations,
      parallelism: PWHASH.RECOMMENDED_PARAMS.parallelism,
    });

    expect(await verifyPin(verificationHash, "MyRecov1")).toBe(true);
    expectSameBytes(await unlockWithPin(pinUnlock, "MyRecov1"), amk);
  });

  it("wrong PIN fails verifyPin before unwrap is attempted", async () => {
    await initCrypto();
    const amk = generateAmk();
    const { verificationHash, pinUnlock } = await registerPinMethod(
      amk,
      "MyRecov1",
    );

    expect(await verifyPin(verificationHash, "WrongPin9")).toBe(false);
    // Caller that gates on verifyPin never reaches unlock; wrong PIN still
    // fails unlock with LockFailedError when called directly.
    await expect(unlockWithPin(pinUnlock, "WrongPin9")).rejects.toBeInstanceOf(
      UnlockFailedError,
    );
  });

  it("verify derivation cannot unwrap (independence of labels/salts)", async () => {
    await initCrypto();
    const amk = generateAmk();
    const pin = "MyRecov1";
    const { verificationHash, pinUnlock } = await registerPinMethod(amk, pin);

    expect(await verifyPin(verificationHash, pin)).toBe(true);

    const verifySalt = base64UrlToBytes(verificationHash.salt);
    const verifyMaterial = derivePinMaterial(
      pin,
      verifySalt,
      verificationHash.argon2Params,
      PIN_VERIFY_KDF_LABEL,
    );
    // Using verify material as AEAD key against the pin wrap must fail.
    expect(() =>
      unwrapAmk(
        { nonce: pinUnlock.nonce, ciphertext: pinUnlock.ciphertext },
        verifyMaterial,
      ),
    ).toThrow(UnlockFailedError);

    // Same PIN + wrap salt but VERIFY label instead of WRAP label → fail.
    const wrapSalt = base64UrlToBytes(pinUnlock.salt!);
    const wrongLabelKey = derivePinMaterial(
      pin,
      wrapSalt,
      pinUnlock.argon2Params!,
      PIN_VERIFY_KDF_LABEL,
    );
    expect(() =>
      unwrapAmk(
        { nonce: pinUnlock.nonce, ciphertext: pinUnlock.ciphertext },
        wrongLabelKey,
      ),
    ).toThrow(UnlockFailedError);

    // Correct wrap path still works.
    const wrapKey = derivePinMaterial(
      pin,
      wrapSalt,
      pinUnlock.argon2Params!,
      PIN_WRAP_KDF_LABEL,
    );
    expectSameBytes(
      unwrapAmk(
        { nonce: pinUnlock.nonce, ciphertext: pinUnlock.ciphertext },
        wrapKey,
      ),
      amk,
    );
  });

  it("setPinMethod after pin-less createAccount adds a PIN", async () => {
    await initCrypto();
    const created = await createAccount("reg-password-1", skipHibp);
    expect(created.pinUnlock).toBeUndefined();
    expect(created.pinVerificationHash).toBeUndefined();

    const enrolled = await setPinMethod(created.amk, "LaterPin9");
    expect(await verifyPin(enrolled.verificationHash, "LaterPin9")).toBe(true);

    const unlocked = await unlockAccountWithPin(
      created.wrappedIdentityKey,
      enrolled.pinUnlock,
      "LaterPin9",
    );
    expectSameBytes(unlocked.identitySecretKeySeed, created.identitySecretKeySeed);
  });

  it("createAccount with pin includes verifier + unlock", async () => {
    await initCrypto();
    const created = await createAccount("reg-password-1", {
      ...skipHibp,
      pin: "SignupPin1",
    });
    expect(created.pinUnlock?.method).toBe("pin");
    expect(created.pinVerificationHash).toBeTruthy();
    expect(
      await verifyPin(created.pinVerificationHash!, "SignupPin1"),
    ).toBe(true);

    await expect(
      setPinMethod(created.amk, "aaaa"),
    ).rejects.toBeInstanceOf(PinPolicyError);
  });
});
