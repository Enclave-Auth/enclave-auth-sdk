/**
 * Typed errors for session-token verification.
 * Primitives PCT / CAST failures keep their `err.name` from
 * `@enclave/pqc-primitives` — do not wrap those away.
 */

/** Token string was not `payload.signature` base64url parts. */
export class MalformedTokenError extends Error {
  override readonly name = "MalformedTokenError";

  constructor(message = "malformed session token") {
    super(message);
  }
}

/** ML-DSA verification failed for the session token. */
export class InvalidSignatureError extends Error {
  override readonly name = "InvalidSignatureError";

  constructor(message = "session token signature invalid") {
    super(message);
  }
}

/** Token `exp` is not strictly greater than now. */
export class ExpiredTokenError extends Error {
  override readonly name = "ExpiredTokenError";

  constructor(message = "session token expired") {
    super(message);
  }
}
