/**
 * Identity signing key wrapped under an already-unwrapped AMK.
 *
 * Distinct from {@link WrappedAmk}: that wraps the AMK under
 * password / recovery-key / PIN. This wraps the account ML-DSA seed
 * under the AMK. Different unlock preconditions — do not merge the types.
 */

/** Ciphertext blob: identitySecretKeySeed encrypted with the AMK. */
export interface WrappedIdentityKey {
  /** Blob schema version (start at 1). */
  formatVersion: number;
  /** Fresh AEAD nonce (base64url). */
  nonce: string;
  /** AEAD ciphertext||tag over the 32-byte identity seed (base64url). */
  ciphertext: string;
}

/** Current {@link WrappedIdentityKey.formatVersion} written by this SDK. */
export const WRAPPED_IDENTITY_KEY_FORMAT_VERSION = 1 as const;
