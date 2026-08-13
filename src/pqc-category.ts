/**
 * NIST post-quantum parameter category for account identity (ML-DSA).
 *
 * Cat5 (default): ML-DSA-87 — existing Enclave Auth accounts.
 * Cat3: ML-DSA-65 — smaller keys/signatures; locked per Application at create.
 */

import { SIG, SIG65 } from "@enclave-technologies/pqc-primitives";

/** ML-DSA parameter category for zero-knowledge identity flows. */
export type PqcCategory = "cat3" | "cat5";

export const DEFAULT_PQC_CATEGORY: PqcCategory = "cat5";

/** Parse API / config values; returns null when invalid. */
export function parsePqcCategory(value: unknown): PqcCategory | null {
  if (value === "cat3" || value === "cat5") {
    return value;
  }
  return null;
}

/** Size constants for the given identity signature category. */
export function sigConstantsForCategory(category: PqcCategory = DEFAULT_PQC_CATEGORY) {
  return category === "cat3" ? SIG65 : SIG;
}
