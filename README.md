# @enclave/auth-sdk

AGPL client/domain cryptography for **Enclave Auth**. Owns identity keygen,
login challenge sign/verify, and session-token mint/verify shared with
`enclave-auth-api` and product APIs. No HTTP, storage, or UI.

All cryptography goes through `@enclave/pqc-primitives` (NIST Category 5 only:
ML-KEM-1024 / ML-DSA-87). There is no suite-selection parameter.

## Setup

```bash
# From Enclave-Inc/enclave-pqc-primitives first if needed:
npm run build

cd ../Enclave-Auth/enclave-auth-sdk
npm install
npm run build
npm test
```

## Usage

```ts
import {
  initCrypto,
  generateIdentityKeyPair,
  signChallenge,
  verifyChallenge,
  mintSessionToken,
  verifySessionToken,
  getLastUsageRecord,
} from "@enclave/auth-sdk";

await initCrypto(); // CAST once at startup

const id = await generateIdentityKeyPair();
// id.secretKeySeed is 32 bytes — never leave the device / auth-api service
```

Call `getLastUsageRecord()` after crypto ops for CBOM attach points (Encrypt).
