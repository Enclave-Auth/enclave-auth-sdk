/**
 * Product-API session verification helpers.
 *
 * Other product backends (sign-api, verify-api, messaging-api, …) should import
 * {@link verifySessionToken} from `@enclave-technologies/auth-sdk` (or this module's
 * re-exports) rather than re-implementing session-token parsing.
 *
 * **Do not reimplement** — copy this file into a product API's `_shared/` only
 * when vendoring the full auth-sdk is impractical; otherwise prefer the SDK
 * import. Verification only needs the Auth service **public** key (from
 * `/.well-known/enclave-auth` or a cached value). Never require the secret seed.
 */

export {
  verifySessionToken,
  type SessionClaims,
} from "./session-token.js";

export {
  ExpiredTokenError,
  InvalidSignatureError,
  MalformedTokenError,
} from "./errors.js";

import { decodePublicKey } from "./identity.js";

/**
 * Fetch the current Auth service public key from the well-known endpoint.
 *
 * @param wellKnownUrl Absolute URL for `/.well-known/enclave-auth`
 *   (or the deployed edge-function equivalent).
 */
export async function fetchAuthServicePublicKey(
  wellKnownUrl: string,
): Promise<{ publicKey: Uint8Array; keyId: string }> {
  const res = await fetch(wellKnownUrl, {
    headers: { Accept: "application/json" },
  });
  if (!res.ok) {
    throw new Error(`failed to fetch auth well-known: HTTP ${res.status}`);
  }
  const body = (await res.json()) as {
    publicKey?: string;
    keyId?: string;
  };
  if (!body.publicKey || !body.keyId) {
    throw new Error("auth well-known response missing publicKey or keyId");
  }
  return {
    publicKey: decodePublicKey(body.publicKey),
    keyId: body.keyId,
  };
}
