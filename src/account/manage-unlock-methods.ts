/**
 * Post-registration unlock-method management (no storage / HTTP).
 */

import {
  registerPasswordMethod,
  registerPinMethod,
  type PinVerificationHash,
  type RegisterPinMethodResult,
  type WrappedAmk,
} from "../amk/index.js";
import { assertPinPolicy } from "../pin-policy.js";
import {
  assertPasswordPolicy,
  type BreachCheckOptions,
} from "../password-policy.js";

/**
 * Produce a new password wrap for an already-unlocked AMK.
 *
 * Runs the same client-side password policy as registration (length + HIBP).
 * Caller must replace the previously stored password {@link WrappedAmk} on
 * the server with this result. This function does not know about persistence.
 */
export async function changePassword(
  amk: Uint8Array,
  newPassword: string,
  passwordPolicy?: BreachCheckOptions,
): Promise<WrappedAmk> {
  await assertPasswordPolicy(newPassword, passwordPolicy);
  return registerPasswordMethod(amk, newPassword);
}

/**
 * Add or rotate a recovery PIN while the account is unlocked.
 *
 * Caller persists {@link RegisterPinMethodResult.verificationHash} and
 * {@link RegisterPinMethodResult.pinUnlock} via auth-enroll-pin (or register).
 */
export async function setPinMethod(
  amk: Uint8Array,
  pin: string,
): Promise<RegisterPinMethodResult> {
  assertPinPolicy(pin);
  return registerPinMethod(amk, pin);
}

export type { PinVerificationHash, RegisterPinMethodResult };
