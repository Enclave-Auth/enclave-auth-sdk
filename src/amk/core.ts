/**
 * Account Master Key (AMK) core: generate and AEAD wrap/unwrap.
 *
 * The AMK is a 32-byte random symmetric key. It is never transmitted or stored
 * in plaintext by this SDK — only wrapped via the password / recovery-key /
 * PIN methods.
 */

import {
  AEAD,
  aeadDecrypt,
  aeadEncrypt,
} from "@enclave-technologies/pqc-primitives";

import { base64UrlToBytes, bytesToBase64Url, utf8Encode } from "../encoding.js";
import { UnlockFailedError } from "./errors.js";

/** AMK length in bytes — matches AES-256-GCM key size. */
export const AMK_BYTES = AEAD.KEY_BYTES;

/** Domain-separated AAD for every AMK wrap (binds ciphertext purpose). */
const AMK_WRAP_AAD = utf8Encode("enclave-auth:amk-wrap:v1");

/** Fill a buffer with CSPRNG bytes (Web Crypto — browser + Node ≥20). */
export function randomBytes(length: number): Uint8Array {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error(`randomBytes length must be a positive integer, got ${length}`);
  }
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

/**
 * Generate a fresh Account Master Key (32 random bytes).
 *
 * Call once at registration. Protect it only via wrap methods afterward.
 */
export function generateAmk(): Uint8Array {
  return randomBytes(AMK_BYTES);
}

export type AmkWrapParts = {
  nonce: string;
  ciphertext: string;
};

/**
 * AEAD-wrap an AMK under a derived key (password / recovery / email path).
 *
 * Uses a fresh random nonce every call. Caller supplies the method-specific
 * derived key; this helper is shared by all unlock methods.
 */
export function wrapAmk(
  amk: Uint8Array,
  derivedKey: Uint8Array,
): AmkWrapParts {
  if (amk.length !== AMK_BYTES) {
    throw new Error(`AMK must be ${AMK_BYTES} bytes, got ${amk.length}`);
  }
  if (derivedKey.length !== AEAD.KEY_BYTES) {
    throw new Error(
      `derived key must be ${AEAD.KEY_BYTES} bytes, got ${derivedKey.length}`,
    );
  }
  const nonce = randomBytes(AEAD.NONCE_BYTES);
  const ciphertext = aeadEncrypt(derivedKey, nonce, amk, AMK_WRAP_AAD);
  return {
    nonce: bytesToBase64Url(nonce),
    ciphertext: bytesToBase64Url(ciphertext),
  };
}

/**
 * AEAD-unwrap an AMK. On any authentication/decoding failure, throws
 * {@link UnlockFailedError} with no oracle detail.
 */
export function unwrapAmk(
  wrapped: { nonce: string; ciphertext: string },
  derivedKey: Uint8Array,
): Uint8Array {
  if (derivedKey.length !== AEAD.KEY_BYTES) {
    throw new UnlockFailedError();
  }
  let nonce: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    nonce = base64UrlToBytes(wrapped.nonce);
    ciphertext = base64UrlToBytes(wrapped.ciphertext);
  } catch {
    throw new UnlockFailedError();
  }
  if (nonce.length !== AEAD.NONCE_BYTES) {
    throw new UnlockFailedError();
  }
  try {
    const plaintext = aeadDecrypt(derivedKey, nonce, ciphertext, AMK_WRAP_AAD);
    if (plaintext.length !== AMK_BYTES) {
      throw new UnlockFailedError();
    }
    return plaintext;
  } catch (err) {
    if (err instanceof UnlockFailedError) {
      throw err;
    }
    throw new UnlockFailedError();
  }
}
