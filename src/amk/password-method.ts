/**
 * Password unlock method for the Account Master Key.
 *
 * Uses Argon2id (memory-hard) because human passwords are low-entropy.
 * Stored wraps always embed the salt + params used at wrap time so later
 * changes to {@link PWHASH.RECOMMENDED_PARAMS} cannot strand old blobs.
 */

import {
  PWHASH,
  generateSalt,
  pwhashDeriveKey,
} from "@enclave/pqc-primitives";

import { base64UrlToBytes, bytesToBase64Url, utf8Encode } from "../encoding.js";
import { wrapAmk, unwrapAmk, AMK_BYTES } from "./core.js";
import { UnlockFailedError } from "./errors.js";
import {
  WRAPPED_AMK_FORMAT_VERSION,
  type Argon2ParamsStored,
  type WrappedAmk,
} from "./types.js";

function copyRecommendedParams(): Argon2ParamsStored {
  const p = PWHASH.RECOMMENDED_PARAMS;
  return {
    memoryCostKib: p.memoryCostKib,
    iterations: p.iterations,
    parallelism: p.parallelism,
  };
}

function assertPasswordWrapped(wrapped: WrappedAmk): void {
  if (
    wrapped.formatVersion !== WRAPPED_AMK_FORMAT_VERSION ||
    wrapped.method !== "password" ||
    typeof wrapped.salt !== "string" ||
    !wrapped.argon2Params
  ) {
    throw new UnlockFailedError();
  }
  const { memoryCostKib, iterations, parallelism } = wrapped.argon2Params;
  if (
    !Number.isInteger(memoryCostKib) ||
    !Number.isInteger(iterations) ||
    !Number.isInteger(parallelism) ||
    memoryCostKib <= 0 ||
    iterations <= 0 ||
    parallelism <= 0
  ) {
    throw new UnlockFailedError();
  }
}

/**
 * Wrap an AMK under a human password (Argon2id + AEAD).
 *
 * Embeds the actual Argon2id params used — not a symbolic "use current
 * recommended" flag — so unlock remains possible if recommendations change.
 */
export async function registerPasswordMethod(
  amk: Uint8Array,
  password: string,
): Promise<WrappedAmk> {
  if (amk.length !== AMK_BYTES) {
    throw new Error(`AMK must be ${AMK_BYTES} bytes, got ${amk.length}`);
  }
  if (password.length === 0) {
    throw new Error("password must not be empty");
  }

  const salt = generateSalt();
  const argon2Params = copyRecommendedParams();
  const derivedKey = pwhashDeriveKey(
    utf8Encode(password),
    salt,
    argon2Params,
  );
  const { nonce, ciphertext } = wrapAmk(amk, derivedKey);

  return {
    formatVersion: WRAPPED_AMK_FORMAT_VERSION,
    method: "password",
    nonce,
    ciphertext,
    salt: bytesToBase64Url(salt),
    argon2Params,
  };
}

/**
 * Unlock an AMK with a password using the salt/params stored on the blob.
 */
export async function unlockWithPassword(
  wrapped: WrappedAmk,
  password: string,
): Promise<Uint8Array> {
  assertPasswordWrapped(wrapped);
  if (password.length === 0) {
    throw new UnlockFailedError();
  }

  let salt: Uint8Array;
  try {
    salt = base64UrlToBytes(wrapped.salt!);
  } catch {
    throw new UnlockFailedError();
  }
  if (salt.length !== PWHASH.SALT_BYTES) {
    throw new UnlockFailedError();
  }

  let derivedKey: Uint8Array;
  try {
    derivedKey = pwhashDeriveKey(
      utf8Encode(password),
      salt,
      wrapped.argon2Params!,
    );
  } catch {
    throw new UnlockFailedError();
  }

  return unwrapAmk(
    { nonce: wrapped.nonce, ciphertext: wrapped.ciphertext },
    derivedKey,
  );
}
