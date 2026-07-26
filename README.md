# @enclave/auth-sdk

AGPL-3.0-or-later client/domain cryptography for **Enclave Auth**. Owns
AMK-protected account identity, login challenge sign/verify, PIN recovery
crypto, and session-token mint/verify shared with `enclave-auth-api` and
product APIs. No HTTP, storage, or UI.

**License stack:** this package is AGPL-3.0-or-later (`LICENSE`). It depends on
`@enclave/pqc-primitives` (Apache-2.0). The product app (`enclave-auth`) and API
(`enclave-auth-api`) are proprietary and are **not** licensed under this
agreement.

All cryptography goes through `@enclave/pqc-primitives` (NIST Category 5 only:
ML-KEM-1024 / ML-DSA-87). There is no suite-selection parameter. User accounts
use one ML-DSA-87 identity per account, wrapped under an Account Master Key
(`createAccount` / account unlock) — not a fresh keypair per device.

## Install

```bash
npm install @enclave/auth-sdk
```

Depends on `@enclave/pqc-primitives` (Apache-2.0), installed automatically.

For local development against sibling repos before packages are on npm:

```bash
cd ../Enclave-Inc/enclave-pqc-primitives && npm run build
cd ../../Enclave-Auth/enclave-auth-sdk
npm install
npm install ../../Enclave-Inc/enclave-pqc-primitives
npm run build
npm test
```

## Setup (from source)

## Usage

```ts
import {
  initCrypto,
  createAccount,
  unlockWithPassword,
  signChallenge,
  getLastUsageRecord,
} from "@enclave/auth-sdk";

await initCrypto(); // CAST once at startup

const account = await createAccount("user-password");
// Show account.recoveryKeyDisplay ONCE; persist wrapped blobs server-side.
// account.identitySecretKeySeed is 32 bytes — never transmit in plaintext.
```

Call `getLastUsageRecord()` after crypto ops for CBOM attach points (Encrypt).

## Password policy

`createAccount` / `changePassword` run NIST SP 800-63B–style checks (min 12
code points, max 128 as an Argon2id resource guard, HIBP k-anonymity breach
check). No composition rules. HIBP outages fail open (`checkFailed`); UI may
warn but must not hard-block solely on that.

The Auth API never receives the plaintext password — only wrap blobs — so
breach/length enforcement is client-side only. Server registration validates
`argon2Params` floors on `passwordUnlock`, not the password itself.

## PIN recovery

Optional alphanumeric PIN (min 8) enrolls two independent Argon2id derivations:
a **verification** digest the API can check, and a **wrap** key used only
client-side to unwrap the existing AMK. See `registerPinMethod` /
`setPinMethod`. Forgot-password never needs an active session — only email +
PIN against stored blobs.

## License

**AGPL-3.0-or-later** — see [`LICENSE`](./LICENSE). A separate commercial
license is available for proprietary products that cannot comply with AGPL
network-copyleft requirements. Contact Enclave for commercial terms.
