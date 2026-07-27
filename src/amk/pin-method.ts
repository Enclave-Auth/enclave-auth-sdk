/**
 * PIN unlock method for the Account Master Key.
 *
 * Two independent Argon2id derivations from the same PIN:
 *   1. Verification — salt_a + label {@link PIN_VERIFY_KDF_LABEL}
 *      → stored as {@link PinVerificationHash} for the Auth API to check
 *        before releasing wrap blobs.
 *   2. Wrap — salt_b + label {@link PIN_WRAP_KDF_LABEL}
 *      → AEAD key for {@link WrappedAmk} (`method: "pin"`). Never sent to
 *        the server as a derived key; only the ciphertext blob is stored.
 *
 * Independence: each path uses its own random salt (Argon2 input differs)
 * and a distinct labeled-KDF domain string on the Argon2 output. Even if an
 * implementation bug reused one salt, different labels still prevent the
 * verify digest from being usable as the wrap key. The server may recompute
 * the verify path only — computing the wrap path would let it decrypt AMKs.
 */

import {
  PWHASH,
  generateSalt,
  labeledKdf32,
  pwhashDeriveKey,
} from "@enclave-technologies/pqc-primitives";

import { base64UrlToBytes, bytesToBase64Url, utf8Encode } from "../encoding.js";
import { wrapAmk, unwrapAmk, AMK_BYTES } from "./core.js";
import { UnlockFailedError } from "./errors.js";
import {
  WRAPPED_AMK_FORMAT_VERSION,
  type Argon2ParamsStored,
  type WrappedAmk,
} from "./types.js";

/** Domain label for PIN → verification digest (server-checkable). */
export const PIN_VERIFY_KDF_LABEL = "enclave-auth:pin-verify:v1";

/** Domain label for PIN → AMK wrap key (client-only). */
export const PIN_WRAP_KDF_LABEL = "enclave-auth:pin-wrap:v1";

/**
 * Server-stored verifier for a PIN (never the wrap key).
 */
export type PinVerificationHash = {
  /** labeledKdf32(verify-label, Argon2id(pin, salt)) as base64url. */
  hash: string;
  salt: string;
  argon2Params: Argon2ParamsStored;
};

export type RegisterPinMethodResult = {
  verificationHash: PinVerificationHash;
  pinUnlock: WrappedAmk;
};

function copyRecommendedParams(): Argon2ParamsStored {
  const p = PWHASH.RECOMMENDED_PARAMS;
  return {
    memoryCostKib: p.memoryCostKib,
    iterations: p.iterations,
    parallelism: p.parallelism,
  };
}

/**
 * Argon2id(pin, salt) then labeled KDF — label selects the domain.
 * Exported for independence tests (verify material ≠ wrap key).
 */
export function derivePinMaterial(
  pin: string,
  salt: Uint8Array,
  argon2Params: Argon2ParamsStored,
  label: string,
): Uint8Array {
  const argonOut = pwhashDeriveKey(utf8Encode(pin), salt, argon2Params);
  return labeledKdf32(label, argonOut);
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

function assertPinWrapped(wrapped: WrappedAmk): void {
  if (
    wrapped.formatVersion !== WRAPPED_AMK_FORMAT_VERSION ||
    wrapped.method !== "pin" ||
    typeof wrapped.salt !== "string" ||
    !wrapped.argon2Params
  ) {
    throw new UnlockFailedError();
  }
  const { memoryCostKib, iterations, parallelism } = wrapped.argon2Params;
  if (
    !Number.isInteger(memoryCostKib) ||
    !Number.isInteger(iterations) ||
    !Number.isInteger(parallelism) ||
    memoryCostKib <= 0 ||
    iterations <= 0 ||
    parallelism <= 0
  ) {
    throw new UnlockFailedError();
  }
}

/**
 * Enroll a PIN: produce a server-checkable verifier + client-only wrap blob.
 */
export async function registerPinMethod(
  amk: Uint8Array,
  pin: string,
): Promise<RegisterPinMethodResult> {
  if (amk.length !== AMK_BYTES) {
    throw new Error(`AMK must be ${AMK_BYTES} bytes, got ${amk.length}`);
  }
  if (pin.length === 0) {
    throw new Error("PIN must not be empty");
  }

  const argon2Params = copyRecommendedParams();

  const verifySalt = generateSalt();
  const verifyDigest = derivePinMaterial(
    pin,
    verifySalt,
    argon2Params,
    PIN_VERIFY_KDF_LABEL,
  );
  const verificationHash: PinVerificationHash = {
    hash: bytesToBase64Url(verifyDigest),
    salt: bytesToBase64Url(verifySalt),
    argon2Params: { ...argon2Params },
  };

  const wrapSalt = generateSalt();
  const wrapKey = derivePinMaterial(
    pin,
    wrapSalt,
    argon2Params,
    PIN_WRAP_KDF_LABEL,
  );
  const { nonce, ciphertext } = wrapAmk(amk, wrapKey);
  const pinUnlock: WrappedAmk = {
    formatVersion: WRAPPED_AMK_FORMAT_VERSION,
    method: "pin",
    nonce,
    ciphertext,
    salt: bytesToBase64Url(wrapSalt),
    argon2Params: { ...argon2Params },
  };

  return { verificationHash, pinUnlock };
}

/**
 * Recompute the verification digest and compare in constant time.
 * Does not touch the wrap derivation.
 */
export async function verifyPin(
  verificationHash: PinVerificationHash,
  pin: string,
): Promise<boolean> {
  if (!pin || typeof verificationHash?.hash !== "string") {
    return false;
  }
  if (
    typeof verificationHash.salt !== "string" ||
    !verificationHash.argon2Params
  ) {
    return false;
  }

  let salt: Uint8Array;
  let expected: Uint8Array;
  try {
    salt = base64UrlToBytes(verificationHash.salt);
    expected = base64UrlToBytes(verificationHash.hash);
  } catch {
    return false;
  }
  if (salt.length !== PWHASH.SALT_BYTES || expected.length === 0) {
    return false;
  }

  try {
    const actual = derivePinMaterial(
      pin,
      salt,
      verificationHash.argon2Params,
      PIN_VERIFY_KDF_LABEL,
    );
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

/**
 * Unlock an AMK with a PIN using the wrap salt/params on the blob.
 * Failures are {@link UnlockFailedError} with no oracle detail.
 */
export async function unlockWithPin(
  wrapped: WrappedAmk,
  pin: string,
): Promise<Uint8Array> {
  assertPinWrapped(wrapped);
  if (pin.length === 0) {
    throw new UnlockFailedError();
  }

  let salt: Uint8Array;
  try {
    salt = base64UrlToBytes(wrapped.salt!);
  } catch {
    throw new UnlockFailedError();
  }
  if (salt.length !== PWHASH.SALT_BYTES) {
    throw new UnlockFailedError();
  }

  let wrapKey: Uint8Array;
  try {
    wrapKey = derivePinMaterial(
      pin,
      salt,
      wrapped.argon2Params!,
      PIN_WRAP_KDF_LABEL,
    );
  } catch {
    throw new UnlockFailedError();
  }

  return unwrapAmk(
    { nonce: wrapped.nonce, ciphertext: wrapped.ciphertext },
    wrapKey,
  );
}
