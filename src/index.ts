/**
 * @enclave-technologies/auth-sdk — Enclave Auth crypto / domain SDK (AGPL).
 *
 * Category 5 only via `@enclave-technologies/pqc-primitives`. No suite parameter.
 *
 * User accounts: AMK-protected identity via `createAccount` / account unlock.
 * Low-level AMK wraps remain on `@enclave-technologies/auth-sdk/amk`.
 */

export { initCrypto } from "./init.js";

export {
  DEFAULT_PQC_CATEGORY,
  parsePqcCategory,
  sigConstantsForCategory,
  type PqcCategory,
} from "./pqc-category.js";

export {
  decodePublicKey,
  encodePublicKey,
  generateIdentityKeyPair,
  type IdentityKeyPair,
} from "./identity.js";

export {
  LOGIN_CHALLENGE_CONTEXT,
  serializeChallenge,
  signChallenge,
  verifyChallenge,
  type Challenge,
} from "./challenge.js";

export {
  SESSION_TOKEN_CONTEXT,
  mintSessionToken,
  serializeClaims,
  verifySessionToken,
  type SessionClaims,
} from "./session-token.js";

export {
  ExpiredTokenError,
  InvalidSignatureError,
  MalformedTokenError,
} from "./errors.js";

export {
  getLastUsageRecord,
  isPairwiseConsistencyFailure,
  isSelfTestFailure,
  type CryptoUsageRecord,
} from "./crypto-usage.js";

export { runImport } from "./migration/orchestrator.js";
export type {
  ImportedUser,
  MigrationRecordStatus,
  MigrationSource,
} from "./migration/types.js";

export { base64UrlToBytes, bytesToBase64Url } from "./encoding.js";

export {
  fetchAuthServicePublicKey,
  type FetchAuthServicePublicKeyOptions,
} from "./session-verify.js";

export {
  AMK_BYTES,
  PIN_VERIFY_KDF_LABEL,
  PIN_WRAP_KDF_LABEL,
  RECOVERY_KEY_BYTES,
  RECOVERY_KEY_KDF_LABEL,
  RECOVERY_KEY_WORD_COUNT,
  UnlockFailedError,
  WRAPPED_AMK_FORMAT_VERSION,
  checkConfirmationWords,
  decodeRecoveryKeyFromDisplay,
  derivePinMaterial,
  encodeRecoveryKeyForDisplay,
  generateAmk,
  generateRecoveryKey,
  getRecoveryKeyWords,
  pickConfirmationIndices,
  registerPasswordMethod,
  registerPinMethod,
  registerRecoveryKeyMethod,
  unlockWithPin as unlockAmkWithPin,
  verifyPin,
  type AmkUnlockMethod,
  type Argon2ParamsStored,
  type PinVerificationHash,
  type RegisterPinMethodResult,
  type WrappedAmk,
} from "./amk/index.js";

export {
  WRAPPED_IDENTITY_KEY_FORMAT_VERSION,
  changePassword,
  createAccount,
  setPinMethod,
  unlockWithPassword,
  unlockWithPin,
  unlockWithRecoveryKey,
  type CreateAccountOptions,
  type CreateAccountResult,
  type UnlockedAccount,
  type WrappedIdentityKey,
} from "./account/index.js";

export {
  HIBP_TIMEOUT_MS,
  MAX_LENGTH,
  MIN_LENGTH,
  PasswordPolicyError,
  assertPasswordPolicy,
  checkBreached,
  checkLength,
  passwordCodePointLength,
  validatePassword,
  type BreachCheckOptions,
  type BreachCheckResult,
  type LengthCheckResult,
  type PasswordPolicyReason,
  type PasswordValidationResult,
} from "./password-policy.js";

export {
  PIN_MAX_LENGTH,
  PIN_MIN_LENGTH,
  PinPolicyError,
  assertPinPolicy,
  checkPinLength,
  checkTrivialPattern,
  pinCodePointLength,
  validatePin,
  type PinPolicyReason,
  type PinValidationResult,
} from "./pin-policy.js";
