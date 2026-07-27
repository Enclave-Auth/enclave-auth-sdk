/**
 * One-shot CAST bootstrap for Enclave Auth.
 *
 * Call once at process / app startup before other SDK crypto. Subsequent ops
 * assume self-tests have already passed and do not re-run CASTs.
 */

import {
  isSelfTestFailure,
  runSelfTests,
} from "@enclave-technologies/pqc-primitives";

let initPromise: Promise<void> | undefined;

/**
 * Run `@enclave-technologies/pqc-primitives` known-answer self-tests once.
 *
 * Throws with `err.name === "SelfTestFailureError"` (see
 * {@link isSelfTestFailure}) if CAST fails. Concurrent callers share the same
 * in-flight promise.
 */
export async function initCrypto(): Promise<void> {
  if (!initPromise) {
    initPromise = runSelfTests().catch((err: unknown) => {
      // Allow a later retry after a failure while preserving typed errors.
      initPromise = undefined;
      throw err;
    });
  }
  return initPromise;
}

/** Clear cached init state — tests only. */
export function resetInitCryptoForTests(): void {
  initPromise = undefined;
}

export { isSelfTestFailure };
