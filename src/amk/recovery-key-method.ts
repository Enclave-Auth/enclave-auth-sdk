/**
 * Recovery-key unlock method for the Account Master Key.
 *
 * The recovery key is high-entropy (32 random bytes). Unlike passwords, it
 * does not need Argon2id — a labeled KDF from `@enclave-technologies/pqc-primitives` is
 * enough. Display encoding is BIP39 (24 words for 256-bit entropy + checksum)
 * via audited `@scure/bip39` — do not hand-roll the wordlist or checksum.
 */

import { entropyToMnemonic, mnemonicToEntropy } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { labeledKdf32 } from "@enclave-technologies/pqc-primitives";

import { wrapAmk, unwrapAmk, AMK_BYTES, randomBytes } from "./core.js";
import { UnlockFailedError } from "./errors.js";
import { WRAPPED_AMK_FORMAT_VERSION, type WrappedAmk } from "./types.js";

/** Domain label for recovery-key → wrapping-key derivation. */
export const RECOVERY_KEY_KDF_LABEL = "enclave-auth:amk-recovery-key:v1";

/** Recovery key / token length in bytes (BIP39 24-word / 256-bit). */
export const RECOVERY_KEY_BYTES = 32;

/** Word count for a 32-byte BIP39 mnemonic. */
export const RECOVERY_KEY_WORD_COUNT = 24;

/**
 * Generate a 32-byte recovery key. Shown to the user exactly once by the
 * product UI — this SDK only generates the bytes.
 */
export function generateRecoveryKey(): Uint8Array {
  return randomBytes(RECOVERY_KEY_BYTES);
}

/**
 * Encode a recovery key as a BIP39 English mnemonic
 * (24 space-separated words, checksum included).
 */
export function encodeRecoveryKeyForDisplay(key: Uint8Array): string {
  if (key.length !== RECOVERY_KEY_BYTES) {
    throw new Error(
      `recovery key must be ${RECOVERY_KEY_BYTES} bytes, got ${key.length}`,
    );
  }
  return entropyToMnemonic(key, wordlist);
}

/**
 * BIP39 mnemonic as an array of 24 words (UI grid rendering).
 */
export function getRecoveryKeyWords(key: Uint8Array): string[] {
  const words = encodeRecoveryKeyForDisplay(key).split(/\s+/u);
  if (words.length !== RECOVERY_KEY_WORD_COUNT) {
    throw new Error(
      `expected ${RECOVERY_KEY_WORD_COUNT} BIP39 words, got ${words.length}`,
    );
  }
  return words;
}

/**
 * Parse a BIP39 mnemonic back to 32 entropy bytes.
 * Tolerant of extra whitespace and inconsistent casing.
 */
export function decodeRecoveryKeyFromDisplay(input: string): Uint8Array {
  const normalized = input.trim().toLowerCase().replace(/\s+/gu, " ");
  if (!normalized) {
    throw new Error("recovery key is empty");
  }
  let entropy: Uint8Array;
  try {
    entropy = mnemonicToEntropy(normalized, wordlist);
  } catch {
    throw new Error("recovery key mnemonic is invalid");
  }
  if (entropy.length !== RECOVERY_KEY_BYTES) {
    throw new Error(
      `recovery key decoded to ${entropy.length} bytes, expected ${RECOVERY_KEY_BYTES}`,
    );
  }
  return entropy;
}

/**
 * Pick `count` distinct random word indices in `[0, 23]` for confirmation UI.
 */
export function pickConfirmationIndices(count = 3): number[] {
  if (!Number.isInteger(count) || count < 1 || count > RECOVERY_KEY_WORD_COUNT) {
    throw new Error(
      `count must be an integer in 1..${RECOVERY_KEY_WORD_COUNT}`,
    );
  }
  const pool = Array.from({ length: RECOVERY_KEY_WORD_COUNT }, (_, i) => i);
  for (let i = pool.length - 1; i > 0; i -= 1) {
    const buf = new Uint8Array(1);
    crypto.getRandomValues(buf);
    const j = buf[0]! % (i + 1);
    const tmp = pool[i]!;
    pool[i] = pool[j]!;
    pool[j] = tmp;
  }
  return pool.slice(0, count).sort((a, b) => a - b);
}

/**
 * Confirm the user re-entered the mnemonic words at `indices`.
 * Comparison is case-insensitive and trims whitespace.
 */
export function checkConfirmationWords(
  words: string[],
  indices: number[],
  submitted: Record<number, string>,
): boolean {
  if (words.length !== RECOVERY_KEY_WORD_COUNT) return false;
  if (indices.length === 0) return false;
  const seen = new Set<number>();
  for (const idx of indices) {
    if (!Number.isInteger(idx) || idx < 0 || idx >= RECOVERY_KEY_WORD_COUNT) {
      return false;
    }
    if (seen.has(idx)) return false;
    seen.add(idx);
    const expected = words[idx]?.trim().toLowerCase() ?? "";
    const got = (submitted[idx] ?? "").trim().toLowerCase();
    if (!expected || !got || expected !== got) return false;
  }
  return true;
}

function deriveRecoveryWrapKey(recoveryKey: Uint8Array): Uint8Array {
  if (recoveryKey.length !== RECOVERY_KEY_BYTES) {
    throw new UnlockFailedError();
  }
  return labeledKdf32(RECOVERY_KEY_KDF_LABEL, recoveryKey);
}

function assertRecoveryWrapped(wrapped: WrappedAmk): void {
  if (
    wrapped.formatVersion !== WRAPPED_AMK_FORMAT_VERSION ||
    wrapped.method !== "recovery-key"
  ) {
    throw new UnlockFailedError();
  }
}

/** Wrap an AMK under a recovery key (labeled KDF + AEAD). */
export async function registerRecoveryKeyMethod(
  amk: Uint8Array,
  recoveryKey: Uint8Array,
): Promise<WrappedAmk> {
  if (amk.length !== AMK_BYTES) {
    throw new Error(`AMK must be ${AMK_BYTES} bytes, got ${amk.length}`);
  }
  if (recoveryKey.length !== RECOVERY_KEY_BYTES) {
    throw new Error(
      `recovery key must be ${RECOVERY_KEY_BYTES} bytes, got ${recoveryKey.length}`,
    );
  }
  const derivedKey = labeledKdf32(RECOVERY_KEY_KDF_LABEL, recoveryKey);
  const { nonce, ciphertext } = wrapAmk(amk, derivedKey);
  return {
    formatVersion: WRAPPED_AMK_FORMAT_VERSION,
    method: "recovery-key",
    nonce,
    ciphertext,
  };
}

/** Unlock an AMK with a recovery key. */
export async function unlockWithRecoveryKey(
  wrapped: WrappedAmk,
  recoveryKey: Uint8Array,
): Promise<Uint8Array> {
  assertRecoveryWrapped(wrapped);
  let derivedKey: Uint8Array;
  try {
    derivedKey = deriveRecoveryWrapKey(recoveryKey);
  } catch (err) {
    if (err instanceof UnlockFailedError) {
      throw err;
    }
    throw new UnlockFailedError();
  }
  return unwrapAmk(
    { nonce: wrapped.nonce, ciphertext: wrapped.ciphertext },
    derivedKey,
  );
}
