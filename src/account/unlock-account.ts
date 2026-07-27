/**
 * Account unlock: AMK method → unwrap identity seed.
 *
 * Failures surface as {@link UnlockFailedError} from either stage with no
 * oracle detail about which step failed.
 */

import { SIG } from "@enclave-technologies/pqc-primitives";

import {
  UnlockFailedError,
  unwrapAmk,
  unlockWithPassword as unlockAmkWithPassword,
  unlockWithPin as unlockAmkWithPin,
  unlockWithRecoveryKey as unlockAmkWithRecoveryKey,
  type WrappedAmk,
} from "../amk/index.js";
import {
  WRAPPED_IDENTITY_KEY_FORMAT_VERSION,
  type WrappedIdentityKey,
} from "./types.js";

export type UnlockedAccount = {
  amk: Uint8Array;
  identitySecretKeySeed: Uint8Array;
};

function assertIdentityWrapped(wrapped: WrappedIdentityKey): void {
  if (
    wrapped.formatVersion !== WRAPPED_IDENTITY_KEY_FORMAT_VERSION ||
    typeof wrapped.nonce !== "string" ||
    typeof wrapped.ciphertext !== "string"
  ) {
    throw new UnlockFailedError();
  }
}

/**
 * Shared second stage: unwrap the identity seed under an unlocked AMK.
 */
function unwrapIdentityUnderAmk(
  wrappedIdentityKey: WrappedIdentityKey,
  amk: Uint8Array,
): Uint8Array {
  assertIdentityWrapped(wrappedIdentityKey);
  const seed = unwrapAmk(
    {
      nonce: wrappedIdentityKey.nonce,
      ciphertext: wrappedIdentityKey.ciphertext,
    },
    amk,
  );
  if (seed.length !== SIG.SECRET_KEY_SEED_BYTES) {
    throw new UnlockFailedError();
  }
  return seed;
}

async function unlockAccount(
  unlockAmk: () => Promise<Uint8Array>,
  wrappedIdentityKey: WrappedIdentityKey,
): Promise<UnlockedAccount> {
  const amk = await unlockAmk();
  try {
    const identitySecretKeySeed = unwrapIdentityUnderAmk(
      wrappedIdentityKey,
      amk,
    );
    return { amk, identitySecretKeySeed };
  } catch (err) {
    if (err instanceof UnlockFailedError) {
      throw err;
    }
    throw new UnlockFailedError();
  }
}

/**
 * Unlock AMK with password, then unwrap the account identity seed.
 */
export async function unlockWithPassword(
  wrappedIdentityKey: WrappedIdentityKey,
  passwordUnlock: WrappedAmk,
  password: string,
): Promise<UnlockedAccount> {
  return unlockAccount(
    () => unlockAmkWithPassword(passwordUnlock, password),
    wrappedIdentityKey,
  );
}

/**
 * Unlock AMK with recovery key, then unwrap the account identity seed.
 */
export async function unlockWithRecoveryKey(
  wrappedIdentityKey: WrappedIdentityKey,
  recoveryUnlock: WrappedAmk,
  recoveryKey: Uint8Array,
): Promise<UnlockedAccount> {
  return unlockAccount(
    () => unlockAmkWithRecoveryKey(recoveryUnlock, recoveryKey),
    wrappedIdentityKey,
  );
}

/**
 * Unlock AMK with PIN, then unwrap the account identity seed.
 */
export async function unlockWithPin(
  wrappedIdentityKey: WrappedIdentityKey,
  pinUnlock: WrappedAmk,
  pin: string,
): Promise<UnlockedAccount> {
  return unlockAccount(
    () => unlockAmkWithPin(pinUnlock, pin),
    wrappedIdentityKey,
  );
}
