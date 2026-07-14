/**
 * Auth session tokens — NOT JWTs.
 *
 * Wire format: `base64url(payload_json) + "." + base64url(signature)`.
 * Signed with ML-DSA-87 under context `enclave-auth:session:v1`.
 *
 * `mintSessionToken` is used by enclave-auth-api (holds the auth service seed).
 * `verifySessionToken` is imported by product APIs with only the auth service
 * public key.
 */

import {
  SIG,
  sigSignWithContext,
  sigVerifyWithContext,
} from "@enclave/pqc-primitives";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  utf8Decode,
  utf8Encode,
} from "./encoding.js";
import {
  ExpiredTokenError,
  InvalidSignatureError,
  MalformedTokenError,
} from "./errors.js";

/** Domain-separation context for session tokens. */
export const SESSION_TOKEN_CONTEXT = "enclave-auth:session:v1" as const;

export type SessionClaims = {
  /** Subject (user id). */
  sub: string;
  /** Audience (product / API identifier). */
  aud: string;
  /** Issued-at (unix seconds, integer). */
  iat: number;
  /** Expiry (unix seconds, integer). */
  exp: number;
  /** Unique token id. */
  jti: string;
};

const SESSION_CONTEXT_BYTES = utf8Encode(SESSION_TOKEN_CONTEXT);

/**
 * Canonical JSON for claims — fixed alphabetical key order, integer times.
 */
export function serializeClaims(claims: SessionClaims): Uint8Array {
  validateClaims(claims);
  const json =
    `{"aud":${JSON.stringify(claims.aud)},` +
    `"exp":${claims.exp},` +
    `"iat":${claims.iat},` +
    `"jti":${JSON.stringify(claims.jti)},` +
    `"sub":${JSON.stringify(claims.sub)}}`;
  return utf8Encode(json);
}

function validateClaims(claims: SessionClaims): void {
  for (const key of ["sub", "aud", "jti"] as const) {
    if (!claims[key] || typeof claims[key] !== "string") {
      throw new Error(`claims.${key} must be a non-empty string`);
    }
  }
  if (!Number.isInteger(claims.iat) || claims.iat < 0) {
    throw new Error("claims.iat must be a non-negative integer");
  }
  if (!Number.isInteger(claims.exp) || claims.exp < 0) {
    throw new Error("claims.exp must be a non-negative integer");
  }
  if (claims.exp <= claims.iat) {
    throw new Error("claims.exp must be greater than claims.iat");
  }
}

function assertSeed(secretKeySeed: Uint8Array): void {
  if (secretKeySeed.length !== SIG.SECRET_KEY_SEED_BYTES) {
    throw new Error(
      `authServiceSecretKeySeed must be ${SIG.SECRET_KEY_SEED_BYTES} bytes`,
    );
  }
}

/**
 * Mint a session token signed by the auth service identity seed.
 *
 * Only enclave-auth-api should hold `authServiceSecretKeySeed`.
 * Call {@link getLastUsageRecord} afterwards for CBOM.
 */
export async function mintSessionToken(
  authServiceSecretKeySeed: Uint8Array,
  claims: SessionClaims,
): Promise<string> {
  assertSeed(authServiceSecretKeySeed);
  const payload = serializeClaims(claims);
  const signature = sigSignWithContext(
    authServiceSecretKeySeed,
    payload,
    SESSION_CONTEXT_BYTES,
  );
  return `${bytesToBase64Url(payload)}.${bytesToBase64Url(signature)}`;
}

/**
 * Verify a session token against the auth service public key.
 *
 * Used by product APIs. Only dependency for verification is
 * `authServicePublicKey` (+ clock for `exp`).
 */
export async function verifySessionToken(
  authServicePublicKey: Uint8Array,
  token: string,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<SessionClaims> {
  if (authServicePublicKey.length !== SIG.PUBLIC_KEY_BYTES) {
    throw new MalformedTokenError(
      `authServicePublicKey must be ${SIG.PUBLIC_KEY_BYTES} bytes`,
    );
  }

  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new MalformedTokenError();
  }

  let payloadBytes: Uint8Array;
  let signature: Uint8Array;
  try {
    payloadBytes = base64UrlToBytes(parts[0]);
    signature = base64UrlToBytes(parts[1]);
  } catch {
    throw new MalformedTokenError("session token parts are not valid base64url");
  }

  if (signature.length !== SIG.SIGNATURE_BYTES) {
    throw new MalformedTokenError(
      `signature must be ${SIG.SIGNATURE_BYTES} bytes`,
    );
  }

  const claims = parseClaimsJson(utf8Decode(payloadBytes));
  const expected = serializeClaims(claims);
  if (!bytesEqual(expected, payloadBytes)) {
    // Reject non-canonical encodings so verify cannot be bypassed by alternate
    // JSON spacing/key order that still parses.
    throw new MalformedTokenError("session token payload is not canonical");
  }

  let ok: boolean;
  try {
    ok = sigVerifyWithContext(
      authServicePublicKey,
      payloadBytes,
      signature,
      SESSION_CONTEXT_BYTES,
    );
  } catch {
    // Attacker-controlled bytes of the right length may fail internal encoding
    // checks; treat that as an invalid signature for callers.
    throw new InvalidSignatureError();
  }
  if (!ok) {
    throw new InvalidSignatureError();
  }

  if (claims.exp <= nowSeconds) {
    throw new ExpiredTokenError();
  }

  return claims;
}

function parseClaimsJson(json: string): SessionClaims {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new MalformedTokenError("session token payload is not JSON");
  }
  if (!parsed || typeof parsed !== "object") {
    throw new MalformedTokenError("session token payload must be an object");
  }
  const obj = parsed as Record<string, unknown>;
  const claims: SessionClaims = {
    sub: String(obj.sub ?? ""),
    aud: String(obj.aud ?? ""),
    iat: Number(obj.iat),
    exp: Number(obj.exp),
    jti: String(obj.jti ?? ""),
  };
  try {
    validateClaims(claims);
  } catch (err) {
    throw new MalformedTokenError(
      err instanceof Error ? err.message : "invalid claims",
    );
  }
  return claims;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}
