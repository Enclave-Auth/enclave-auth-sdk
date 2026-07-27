/**
 * Password policy (NIST SP 800-63B–aligned): length + known-breach check.
 *
 * Explicitly **not** composition rules (no forced upper/lower/digit/symbol).
 * Composition tends to push users toward predictable patterns and does not
 * meaningfully resist offline guessing of Argon2id-wrapped AMKs — length and
 * uniqueness against known breaches do.
 *
 * # SHA-1 boundary
 *
 * Breach lookup uses SHA-1 only as the **public key into the HIBP range API**
 * (k-anonymity). It is not used for password storage or key derivation. Do
 * **not** add SHA-1 to `@enclave-technologies/pqc-primitives` for this — that crate is for
 * PQC / AEAD / Argon2id / labeled KDF, not breach-list lookup hashes. We use
 * `globalThis.crypto.subtle.digest("SHA-1", …)` (Web Crypto), available in
 * modern browsers, Deno, and Node ≥18 with `webcrypto`.
 *
 * # Zero-knowledge note
 *
 * The Auth server never receives the plaintext password (only AMK wrap blobs).
 * HIBP / length enforcement for the password itself is therefore **client-side**
 * (this module + callers such as `createAccount`). Server-side can only sanity-
 * check wrap metadata (e.g. argon2Params floors), which is not a substitute
 * for these checks.
 */

/** Minimum password length in Unicode code points (NIST-oriented floor). */
export const MIN_LENGTH = 12;

/**
 * Maximum password length in Unicode code points.
 *
 * This is a **resource-exhaustion guard** against feeding enormous strings into
 * Argon2id — not a security-strength rule. Attackers don't gain from longer
 * passwords; our servers/clients do lose if someone submits megabyte strings.
 */
export const MAX_LENGTH = 128;

/** HIBP range request timeout (ms). */
export const HIBP_TIMEOUT_MS = 4_000;

/**
 * Timeout choice: 4s is short enough that a hung breach API does not stall
 * registration UX, and long enough for typical CDN round-trips. Failures
 * fail open (see {@link checkBreached}).
 */

export type LengthReason = "too_short" | "too_long";

export type PasswordPolicyReason = LengthReason | "breached";

export type LengthCheckResult = {
  valid: boolean;
  reason?: LengthReason;
};

export type BreachCheckResult = {
  breached: boolean;
  /** True when HIBP could not be reached — fail-open, do not hard-block. */
  checkFailed?: boolean;
};

export type PasswordValidationResult = {
  valid: boolean;
  reason?: PasswordPolicyReason;
  checkFailed?: boolean;
};

export type BreachCheckOptions = {
  /** Injectable fetch (tests / Deno custom stacks). Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
  /** Override HIBP timeout; default {@link HIBP_TIMEOUT_MS}. */
  timeoutMs?: number;
};

/**
 * Thrown by registration / password-change helpers when policy rejects.
 */
export class PasswordPolicyError extends Error {
  override readonly name = "PasswordPolicyError";
  readonly reason: PasswordPolicyReason;

  constructor(reason: PasswordPolicyReason) {
    super(`password rejected: ${reason}`);
    this.reason = reason;
  }
}

/**
 * Count Unicode **code points** (via string iteration), not UTF-8 bytes and
 * not UTF-16 code units alone.
 *
 * Why code points: users experience “characters”; counting UTF-8 bytes would
 * make emoji / non-Latin scripts hit MIN_LENGTH unfairly, while naive
 * `password.length` in JS is UTF-16 code units (surrogate pairs = 2).
 * Spreading / iterating a JS string yields code points. Complex grapheme
 * clusters (ZWJ emoji) may still count as multiple code points — accepting
 * that as a practical tradeoff without a full grapheme-break library.
 */
export function passwordCodePointLength(password: string): number {
  return [...password].length;
}

/** Length-only check (no network). */
export function checkLength(password: string): LengthCheckResult {
  const len = passwordCodePointLength(password);
  if (len < MIN_LENGTH) {
    return { valid: false, reason: "too_short" };
  }
  if (len > MAX_LENGTH) {
    return { valid: false, reason: "too_long" };
  }
  return { valid: true };
}

async function sha1HexUpper(password: string): Promise<string> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle?.digest) {
    throw new Error(
      "Web Crypto subtle.digest(SHA-1) is unavailable in this runtime",
    );
  }
  const data = new TextEncoder().encode(password);
  const digest = await subtle.digest("SHA-1", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/**
 * Have I Been Pwned Passwords k-anonymity range check.
 *
 * Only the first 5 hex chars of SHA-1(password) are sent to HIBP — never the
 * password itself or the full hash. On timeout / network / non-OK response:
 * **fail open** `{ breached: false, checkFailed: true }` so a third-party
 * outage does not block registration. Callers may surface a soft warning via
 * `checkFailed` but must not hard-block solely on it.
 */
export async function checkBreached(
  password: string,
  options: BreachCheckOptions = {},
): Promise<BreachCheckResult> {
  let fullHash: string;
  try {
    fullHash = await sha1HexUpper(password);
  } catch {
    return { breached: false, checkFailed: true };
  }

  const prefix = fullHash.slice(0, 5);
  const suffix = fullHash.slice(5);
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? HIBP_TIMEOUT_MS;

  if (typeof fetchImpl !== "function") {
    return { breached: false, checkFailed: true };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchImpl(
      `https://api.pwnedpasswords.com/range/${prefix}`,
      {
        method: "GET",
        headers: {
          // HIBP asks for a User-Agent identifying the consumer.
          "User-Agent": "enclave-auth-sdk-password-policy",
          "Add-Padding": "true",
        },
        signal: controller.signal,
      },
    );
    if (!response.ok) {
      return { breached: false, checkFailed: true };
    }
    const body = await response.text();
    const lines = body.split(/\r?\n/u);
    for (const line of lines) {
      const [hashSuffix] = line.trim().split(":");
      if (hashSuffix && hashSuffix.toUpperCase() === suffix) {
        return { breached: true };
      }
    }
    return { breached: false };
  } catch {
    // AbortError, network failure, etc. — fail open.
    return { breached: false, checkFailed: true };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Full policy: length first (fail fast, no network), then HIBP if length ok.
 */
export async function validatePassword(
  password: string,
  options: BreachCheckOptions = {},
): Promise<PasswordValidationResult> {
  const length = checkLength(password);
  if (!length.valid) {
    return { valid: false, reason: length.reason };
  }
  const breach = await checkBreached(password, options);
  if (breach.breached) {
    return {
      valid: false,
      reason: "breached",
      checkFailed: breach.checkFailed,
    };
  }
  return { valid: true, checkFailed: breach.checkFailed };
}

/**
 * Assert password passes policy; throw {@link PasswordPolicyError} on hard fail.
 * HIBP `checkFailed` alone does not throw (fail-open).
 */
export async function assertPasswordPolicy(
  password: string,
  options: BreachCheckOptions = {},
): Promise<{ checkFailed?: boolean }> {
  const result = await validatePassword(password, options);
  if (!result.valid && result.reason) {
    throw new PasswordPolicyError(result.reason);
  }
  return { checkFailed: result.checkFailed };
}
