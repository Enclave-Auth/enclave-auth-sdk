/**
 * Account Master Key (AMK) — generate + parallel unlock wraps.
 *
 * Standalone module. Wiring into identity/registration/login is out of scope
 * here; this package only turns passwords / recovery keys / PINs into
 * independently unlockable AEAD wraps of the same 32-byte AMK.
 */

export {
  AMK_BYTES,
  generateAmk,
  randomBytes,
  unwrapAmk,
  wrapAmk,
  type AmkWrapParts,
} from "./core.js";

export { UnlockFailedError } from "./errors.js";

export {
  registerPasswordMethod,
  unlockWithPassword,
} from "./password-method.js";

export {
  RECOVERY_KEY_BYTES,
  RECOVERY_KEY_KDF_LABEL,
  RECOVERY_KEY_WORD_COUNT,
  checkConfirmationWords,
  decodeRecoveryKeyFromDisplay,
  encodeRecoveryKeyForDisplay,
  generateRecoveryKey,
  getRecoveryKeyWords,
  pickConfirmationIndices,
  registerRecoveryKeyMethod,
  unlockWithRecoveryKey,
} from "./recovery-key-method.js";

export {
  PIN_VERIFY_KDF_LABEL,
  PIN_WRAP_KDF_LABEL,
  derivePinMaterial,
  registerPinMethod,
  unlockWithPin,
  verifyPin,
  type PinVerificationHash,
  type RegisterPinMethodResult,
} from "./pin-method.js";

export {
  WRAPPED_AMK_FORMAT_VERSION,
  type AmkUnlockMethod,
  type Argon2ParamsStored,
  type WrappedAmk,
} from "./types.js";
