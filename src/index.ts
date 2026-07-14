/**
 * @enclave/auth-sdk — Enclave Auth crypto / domain SDK (AGPL).
 *
 * Category 5 only via `@enclave/pqc-primitives`. No suite parameter.
 */

export { initCrypto } from "./init.js";

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

export { fetchAuthServicePublicKey } from "./session-verify.js";
