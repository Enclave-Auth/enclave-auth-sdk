/**
 * Account registration cryptography (no HTTP / persistence).
 *
 * One AMK + one ML-DSA-87 identity per account. Parallel password and recovery
 * wraps protect the AMK; the identity seed is wrapped under the AMK.
 * An optional PIN enrolls a server-checkable verifier + wrap for recovery.
 */

import {
  generateAmk,
  generateRecoveryKey,
  encodeRecoveryKeyForDisplay,
  registerPasswordMethod,
  registerPinMethod,
  registerRecoveryKeyMethod,
  wrapAmk,
  type PinVerificationHash,
  type WrappedAmk,
} from "../amk/index.js";
import { generateIdentityKeyPair } from "../identity.js";
import { assertPinPolicy } from "../pin-policy.js";
import {
  assertPasswordPolicy,
  type BreachCheckOptions,
} from "../password-policy.js";
import {
  WRAPPED_IDENTITY_KEY_FORMAT_VERSION,
  type WrappedIdentityKey,
} from "./types.js";

import type { PqcCategory } from "../pqc-category.js";
import { DEFAULT_PQC_CATEGORY } from "../pqc-category.js";

/** Optional hooks (tests inject mock HIBP fetch; optional PIN at signup). */
export type CreateAccountOptions = {
  passwordPolicy?: BreachCheckOptions;
  /** Optional recovery PIN (alphanumeric secondary credential). */
  pin?: string;
  /** ML-DSA parameter category — must match the Application (default cat5). */
  pqcCategory?: PqcCategory;
};

export type CreateAccountResult = {
  /** Fresh Account Master Key (caller may cache locally after unwrap). */
  amk: Uint8Array;
  /** Account ML-DSA-87 public key (persist server-side). */
  identityPublicKey: Uint8Array;
  /** Account ML-DSA-87 seed — never transmit; wrap / cache only. */
  identitySecretKeySeed: Uint8Array;
  /** Identity seed encrypted under the AMK. */
  wrappedIdentityKey: WrappedIdentityKey;
  /** AMK encrypted under the registration password. */
  passwordUnlock: WrappedAmk;
  /** Raw recovery key — display ONCE; not stored by this SDK. */
  recoveryKey: Uint8Array;
  /** Human-transcribable BIP39 mnemonic (24 words) for {@link recoveryKey}. */
  recoveryKeyDisplay: string;
  /** AMK encrypted under the recovery key. */
  recoveryUnlock: WrappedAmk;
  /** Present when {@link CreateAccountOptions.pin} was provided. */
  pinVerificationHash?: PinVerificationHash;
  /** Present when {@link CreateAccountOptions.pin} was provided. */
  pinUnlock?: WrappedAmk;
};

/**
 * Create a new account's crypto material.
 *
 * Order: password policy → optional PIN policy → AMK → identity → wraps.
 * Does not call enclave-auth-api or any storage.
 */
export async function createAccount(
  password: string,
  options: CreateAccountOptions = {},
): Promise<CreateAccountResult> {
  // Length + HIBP before any wrap work. Breach check is client-only by design
  // (zero-knowledge: auth-register never receives the plaintext password).
  await assertPasswordPolicy(password, options.passwordPolicy);

  if (options.pin !== undefined) {
    assertPinPolicy(options.pin);
  }

  const amk = generateAmk();
  const pqcCategory = options.pqcCategory ?? DEFAULT_PQC_CATEGORY;
  const identity = await generateIdentityKeyPair(pqcCategory);

  // wrapAmk(plaintext, wrappingKey): identity seed under the AMK.
  const identityParts = wrapAmk(identity.secretKeySeed, amk);
  const wrappedIdentityKey: WrappedIdentityKey = {
    formatVersion: WRAPPED_IDENTITY_KEY_FORMAT_VERSION,
    nonce: identityParts.nonce,
    ciphertext: identityParts.ciphertext,
  };

  const passwordUnlock = await registerPasswordMethod(amk, password);

  const recoveryKey = generateRecoveryKey();
  const recoveryKeyDisplay = encodeRecoveryKeyForDisplay(recoveryKey);
  const recoveryUnlock = await registerRecoveryKeyMethod(amk, recoveryKey);

  const result: CreateAccountResult = {
    amk,
    identityPublicKey: identity.publicKey,
    identitySecretKeySeed: identity.secretKeySeed,
    wrappedIdentityKey,
    passwordUnlock,
    recoveryKey,
    recoveryKeyDisplay,
    recoveryUnlock,
  };

  if (options.pin !== undefined) {
    const enrolled = await registerPinMethod(amk, options.pin);
    result.pinVerificationHash = enrolled.verificationHash;
    result.pinUnlock = enrolled.pinUnlock;
  }

  return result;
}
