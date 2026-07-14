/**
 * CBOM / usage attach point for Encrypt.
 *
 * Re-exports the primitives last-usage record so SDK callers never lose the
 * algorithm metadata produced by `@enclave/pqc-primitives`.
 */

export {
  getLastUsageRecord,
  isPairwiseConsistencyFailure,
  isSelfTestFailure,
  type CryptoUsageRecord,
} from "@enclave/pqc-primitives";
