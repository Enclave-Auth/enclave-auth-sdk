# AGENTS.md — enclave-auth-sdk

AGPL client-side crypto / domain SDK for **Enclave Auth**.

## Rules

1. Category 5 crypto only via `@enclave/pqc-primitives`. Exception: BIP39
   mnemonic encode/decode uses audited `@scure/bip39` (wordlist + checksum) —
   do not hand-roll BIP39.
2. Category 5 exclusively (ML-KEM-1024 / ML-DSA-87). No suite parameter.
3. Prefer seed-form secret keys in public APIs (`secretKeySeed`). Expand only
   transiently if a specific primitives call requires it (current primitives
   accept seed form for sign / decapsulate).
4. One ML-DSA-87 identity per **account**, protected by AMK wraps — not a
   fresh keypair per device. Use `createAccount` / account unlock for users;
   keep `generateIdentityKeyPair` for auth-service keys and low-level use.
5. Optional PIN recovery uses two independent Argon2id+label derivations
   (`pin-verify` vs `pin-wrap`). Server may only recompute verify; never wrap.
6. No HTTP handlers, database access, or UI in this package.
7. Do not swallow `PairwiseConsistencyFailureError` / `SelfTestFailureError`
   (`err.name` / helpers from primitives). Propagate `UnlockFailedError`
   without wrapping or adding oracle detail.
8. Challenge and session-token modules must stay isomorphic (browser + Node).

## Commands

```bash
npm install
npm run build
npm test
```

Build sibling `@enclave/pqc-primitives` (WASM) before linking if `dist/` is missing.
