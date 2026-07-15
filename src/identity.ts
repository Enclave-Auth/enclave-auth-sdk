/**
 * ML-DSA-87 identity key material (account or service).
 *
 * End-user accounts: generate once via `createAccount` (AMK-protected).
 * There is one signing keypair per account — not one per device. Devices that
 * can unlock the AMK recover the same `secretKeySeed`.
 *
 * This module still exposes {@link generateIdentityKeyPair} as the low-level
 * generator (also used for auth-service session-token keys). Prefer
 * `createAccount` for user registration.
 *
 * Public API always exposes the 32-byte seed form as `secretKeySeed`. The seed
 * is never transmitted to enclave-auth-api as a plaintext credential blob for
 * end-users — only as ciphertext under the AMK (`WrappedIdentityKey`).
 *
 * Current `@enclave/pqc-primitives` `sigSign` / `sigSignWithContext` accept the
 * seed form directly — no expand-before-sign is required.
 */

import {
  SIG,
  sigGenerateKeypair,
} from "@enclave/pqc-primitives";

import { base64UrlToBytes, bytesToBase64Url } from "./encoding.js";

export type IdentityKeyPair = {
  publicKey: Uint8Array;
  /** Preferred ML-DSA-87 seed (32 bytes). Never transmit in plaintext. */
  secretKeySeed: Uint8Array;
};

/**
 * Generate a fresh ML-DSA-87 identity keypair (low-level).
 *
 * For user accounts, call `createAccount` instead so the seed is wrapped under
 * an AMK. This remains public for auth-service keys and tests.
 *
 * Propagates `PairwiseConsistencyFailureError` from primitives (`err.name` /
 * `isPairwiseConsistencyFailure`) without wrapping.
 *
 * CBOM: call {@link getLastUsageRecord} after this returns.
 */
export async function generateIdentityKeyPair(): Promise<IdentityKeyPair> {
  const kp = sigGenerateKeypair();
  if (kp.publicKey.length !== SIG.PUBLIC_KEY_BYTES) {
    throw new Error(
      `unexpected ML-DSA-87 public key length: ${kp.publicKey.length}`,
    );
  }
  if (kp.secretKey.length !== SIG.SECRET_KEY_SEED_BYTES) {
    throw new Error(
      `unexpected ML-DSA-87 secret seed length: ${kp.secretKey.length}`,
    );
  }
  return {
    publicKey: kp.publicKey,
    secretKeySeed: kp.secretKey,
  };
}

/** Encode an ML-DSA-87 public key as base64url for HTTP/JSON. */
export function encodePublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== SIG.PUBLIC_KEY_BYTES) {
    throw new Error(
      `public key must be ${SIG.PUBLIC_KEY_BYTES} bytes, got ${publicKey.length}`,
    );
  }
  return bytesToBase64Url(publicKey);
}

/** Decode a base64url ML-DSA-87 public key. */
export function decodePublicKey(value: string): Uint8Array {
  const bytes = base64UrlToBytes(value);
  if (bytes.length !== SIG.PUBLIC_KEY_BYTES) {
    throw new Error(
      `public key must be ${SIG.PUBLIC_KEY_BYTES} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}
