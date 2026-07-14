# AGENTS.md — enclave-auth-sdk

AGPL client-side crypto / domain SDK for **Enclave Auth**.

## Rules

1. Crypto only via `@enclave/pqc-primitives` — no other crypto libraries.
2. Category 5 exclusively (ML-KEM-1024 / ML-DSA-87). No suite parameter.
3. Prefer seed-form secret keys in public APIs (`secretKeySeed`). Expand only
   transiently if a specific primitives call requires it (current primitives
   accept seed form for sign / decapsulate).
4. No HTTP handlers, database access, or UI in this package.
5. Do not swallow `PairwiseConsistencyFailureError` / `SelfTestFailureError`
   (`err.name` / helpers from primitives).
6. Challenge and session-token modules must stay isomorphic (browser + Node).

## Commands

```bash
npm install
npm run build
npm test
```

Build sibling `@enclave/pqc-primitives` (WASM) before linking if `dist/` is missing.
