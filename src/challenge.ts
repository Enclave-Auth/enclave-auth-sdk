/**
 * Login challenge sign / verify (isomorphic).
 *
 * Client signs with the account `secretKeySeed` (recovered after AMK unlock);
 * server verifies with the registered account public key only. Serialization
 * is canonical JSON with fixed key order.
 *
 * Primitives accept the 32-byte seed form for `sigSignWithContext` — seeds are
 * passed through without expansion. This module does not care how the seed was
 * obtained (AMK unlock vs. service key).
 */

import {
  SIG,
  sigSignWithContext,
  sigVerifyWithContext,
} from "@enclave-technologies/pqc-primitives";

import { base64UrlToBytes, bytesToBase64Url, utf8Encode } from "./encoding.js";

/** Fixed domain-separation context for login challenges. */
export const LOGIN_CHALLENGE_CONTEXT = "enclave-auth:login:v1" as const;

export type Challenge = {
  /** Server-issued nonce (base64url). */
  nonce: string;
  /** Unix epoch milliseconds (integer). */
  issuedAt: number;
  /** Domain-separation string (≤ 255 bytes UTF-8), e.g. LOGIN_CHALLENGE_CONTEXT. */
  context: string;
};

/**
 * Canonical JSON for a challenge — stable key order, integer `issuedAt` only.
 * Both sign and verify MUST use this exact bytestring.
 */
export function serializeChallenge(challenge: Challenge): Uint8Array {
  validateChallenge(challenge);
  // Fixed key order: context, issuedAt, nonce (alphabetical).
  const json =
    `{"context":${jsonString(challenge.context)},` +
    `"issuedAt":${challenge.issuedAt},` +
    `"nonce":${jsonString(challenge.nonce)}}`;
  return utf8Encode(json);
}

function jsonString(value: string): string {
  return JSON.stringify(value);
}

function validateChallenge(challenge: Challenge): void {
  if (!challenge.nonce.trim()) {
    throw new Error("challenge.nonce must not be empty");
  }
  if (!Number.isInteger(challenge.issuedAt) || challenge.issuedAt < 0) {
    throw new Error("challenge.issuedAt must be a non-negative integer");
  }
  if (!challenge.context) {
    throw new Error("challenge.context must not be empty");
  }
  const contextBytes = utf8Encode(challenge.context);
  if (contextBytes.length > SIG.MAX_CONTEXT_BYTES) {
    throw new Error(
      `challenge.context must be ≤ ${SIG.MAX_CONTEXT_BYTES} bytes UTF-8`,
    );
  }
}

function assertSeed(secretKeySeed: Uint8Array): void {
  if (secretKeySeed.length !== SIG.SECRET_KEY_SEED_BYTES) {
    throw new Error(
      `secretKeySeed must be ${SIG.SECRET_KEY_SEED_BYTES} bytes, got ${secretKeySeed.length}`,
    );
  }
}

/**
 * Sign a login challenge with an account (or service) identity seed.
 *
 * Returns base64url signature. Call {@link getLastUsageRecord} afterwards for CBOM.
 */
export async function signChallenge(
  secretKeySeed: Uint8Array,
  challenge: Challenge,
): Promise<string> {
  assertSeed(secretKeySeed);
  const message = serializeChallenge(challenge);
  const context = utf8Encode(challenge.context);
  // Seed form is accepted by sigSignWithContext (32 B).
  const signature = sigSignWithContext(secretKeySeed, message, context);
  return bytesToBase64Url(signature);
}

/**
 * Verify a login challenge signature (server-side public-key only).
 */
export async function verifyChallenge(
  publicKey: Uint8Array,
  challenge: Challenge,
  signatureB64: string,
): Promise<boolean> {
  if (publicKey.length !== SIG.PUBLIC_KEY_BYTES) {
    throw new Error(
      `publicKey must be ${SIG.PUBLIC_KEY_BYTES} bytes, got ${publicKey.length}`,
    );
  }
  const message = serializeChallenge(challenge);
  const context = utf8Encode(challenge.context);
  const signature = base64UrlToBytes(signatureB64);
  if (signature.length !== SIG.SIGNATURE_BYTES) {
    throw new Error(
      `signature must be ${SIG.SIGNATURE_BYTES} bytes, got ${signature.length}`,
    );
  }
  return sigVerifyWithContext(publicKey, message, signature, context);
}
