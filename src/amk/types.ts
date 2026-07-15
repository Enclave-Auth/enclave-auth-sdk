/**
 * Serializable AMK wrap blobs.
 *
 * `enclave-auth-api` persists these; this SDK never stores them itself.
 */

/** Supported parallel unlock methods for a single Account Master Key. */
export type AmkUnlockMethod = "password" | "recovery-key" | "pin";

/** Argon2id cost parameters stored with password / PIN wraps. */
export type Argon2ParamsStored = {
  memoryCostKib: number;
  iterations: number;
  parallelism: number;
};

/**
 * One method's ciphertext for the Account Master Key.
 *
 * Format can evolve via {@link WrappedAmk.formatVersion}. Unlock always uses
 * the salt/params embedded in *this* blob — never "current recommended"
 * defaults at unlock time.
 */
export interface WrappedAmk {
  /** Blob schema version (start at 1). */
  formatVersion: number;
  /** Which unlock method produced this wrap. */
  method: AmkUnlockMethod;
  /** Fresh AEAD nonce (base64url); never reused. */
  nonce: string;
  /** AEAD ciphertext||tag over the AMK (base64url). */
  ciphertext: string;
  /** Password / PIN methods: Argon2id salt (base64url). */
  salt?: string;
  /** Password / PIN methods: params actually used at wrap time. */
  argon2Params?: Argon2ParamsStored;
}

/** Current {@link WrappedAmk.formatVersion} written by this SDK. */
export const WRAPPED_AMK_FORMAT_VERSION = 1 as const;
