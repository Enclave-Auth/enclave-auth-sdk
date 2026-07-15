/**
 * AMK-protected account identity (registration + unlock orchestration).
 *
 * Crypto-only — persistence and HTTP live in enclave-auth-api.
 */

export { UnlockFailedError } from "../amk/errors.js";

export {
  createAccount,
  type CreateAccountOptions,
  type CreateAccountResult,
} from "./create-account.js";

export {
  changePassword,
  setPinMethod,
} from "./manage-unlock-methods.js";

export {
  unlockWithPassword,
  unlockWithPin,
  unlockWithRecoveryKey,
  type UnlockedAccount,
} from "./unlock-account.js";

export {
  WRAPPED_IDENTITY_KEY_FORMAT_VERSION,
  type WrappedIdentityKey,
} from "./types.js";
