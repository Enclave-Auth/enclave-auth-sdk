/**
 * ML-DSA identity key material (account or service).
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
 * {@link PqcCategory} selects ML-DSA-87 (cat5, default) or ML-DSA-65 (cat3).
 */

import {
  sig65GenerateKeypair,
  sigGenerateKeypair,
} from "@enclave-technologies/pqc-primitives";

import { base64UrlToBytes, bytesToBase64Url } from "./encoding.js";
import {
  DEFAULT_PQC_CATEGORY,
  sigConstantsForCategory,
  type PqcCategory,
} from "./pqc-category.js";

export type IdentityKeyPair = {
  publicKey: Uint8Array;
  /** Preferred ML-DSA seed (32 bytes). Never transmit in plaintext. */
  secretKeySeed: Uint8Array;
};

/**
 * Generate a fresh ML-DSA identity keypair (low-level).
 *
 * For user accounts, call `createAccount` instead so the seed is wrapped under
 * an AMK. Auth-service session keys remain cat5 (default).
 *
 * Propagates `PairwiseConsistencyFailureError` from primitives without wrapping.
 *
 * CBOM: call {@link getLastUsageRecord} after this returns.
 */
export async function generateIdentityKeyPair(
  pqcCategory: PqcCategory = DEFAULT_PQC_CATEGORY,
): Promise<IdentityKeyPair> {
  const sig = sigConstantsForCategory(pqcCategory);
  const kp = pqcCategory === "cat3"
    ? sig65GenerateKeypair()
    : sigGenerateKeypair();

  if (kp.publicKey.length !== sig.PUBLIC_KEY_BYTES) {
    throw new Error(
      `unexpected ML-DSA public key length: ${kp.publicKey.length}`,
    );
  }
  if (kp.secretKey.length !== sig.SECRET_KEY_SEED_BYTES) {
    throw new Error(
      `unexpected ML-DSA secret seed length: ${kp.secretKey.length}`,
    );
  }
  return {
    publicKey: kp.publicKey,
    secretKeySeed: kp.secretKey,
  };
}

/** Encode an ML-DSA public key as base64url for HTTP/JSON. */
export function encodePublicKey(
  publicKey: Uint8Array,
  pqcCategory: PqcCategory = DEFAULT_PQC_CATEGORY,
): string {
  const expected = sigConstantsForCategory(pqcCategory).PUBLIC_KEY_BYTES;
  if (publicKey.length !== expected) {
    throw new Error(
      `public key must be ${expected} bytes, got ${publicKey.length}`,
    );
  }
  return bytesToBase64Url(publicKey);
}

/** Decode a base64url ML-DSA public key. */
export function decodePublicKey(
  value: string,
  pqcCategory: PqcCategory = DEFAULT_PQC_CATEGORY,
): Uint8Array {
  const expected = sigConstantsForCategory(pqcCategory).PUBLIC_KEY_BYTES;
  const bytes = base64UrlToBytes(value);
  if (bytes.length !== expected) {
    throw new Error(
      `public key must be ${expected} bytes, got ${bytes.length}`,
    );
  }
  return bytes;
}
