/**
 * PIN policy for the secondary recovery credential.
 *
 * PINs are short alphanumeric secrets (not 4–6 digit codes). Cheap local checks
 * only — no HIBP network call (disproportionate for a secondary credential).
 */

export const PIN_MIN_LENGTH = 8;

/** Soft upper bound — resource guard, not a strength rule. */
export const PIN_MAX_LENGTH = 64;

export type PinPolicyReason =
  | "too_short"
  | "too_long"
  | "trivial_pattern";

export type PinValidationResult = {
  valid: boolean;
  reason?: PinPolicyReason;
};

export class PinPolicyError extends Error {
  override readonly name = "PinPolicyError";
  readonly reason: PinPolicyReason;

  constructor(reason: PinPolicyReason) {
    super(`PIN rejected: ${reason}`);
    this.reason = reason;
  }
}

/** Count Unicode code points (same rationale as password policy). */
export function pinCodePointLength(pin: string): number {
  return [...pin].length;
}

export function checkPinLength(pin: string): PinValidationResult {
  const len = pinCodePointLength(pin);
  if (len < PIN_MIN_LENGTH) {
    return { valid: false, reason: "too_short" };
  }
  if (len > PIN_MAX_LENGTH) {
    return { valid: false, reason: "too_long" };
  }
  return { valid: true };
}

/** Short common / obviously-weak PIN blocklist (lowercase ASCII compare). */
const COMMON_PIN_BLOCKLIST = new Set([
  "password",
  "password1",
  "12345678",
  "123456789",
  "1234567890",
  "qwertyui",
  "qwerty123",
  "abcdefgh",
  "letmein1",
  "welcome1",
  "iloveyou",
  "admin123",
  "passw0rd",
]);

/**
 * Reject all-same-character, simple sequential runs, and a short blocklist.
 * Intentionally cheap — not a substitute for password-grade policy.
 */
export function checkTrivialPattern(pin: string): PinValidationResult {
  const normalized = pin.toLowerCase();
  const points = [...normalized];
  if (points.length === 0) {
    return { valid: false, reason: "trivial_pattern" };
  }

  if (points.every((c) => c === points[0])) {
    return { valid: false, reason: "trivial_pattern" };
  }

  if (isSimpleSequential(points)) {
    return { valid: false, reason: "trivial_pattern" };
  }

  if (COMMON_PIN_BLOCKLIST.has(normalized)) {
    return { valid: false, reason: "trivial_pattern" };
  }

  return { valid: true };
}

function isSimpleSequential(points: string[]): boolean {
  if (points.length < 4) return false;
  let ascending = true;
  let descending = true;
  for (let i = 1; i < points.length; i += 1) {
    const prev = points[i - 1]!.codePointAt(0)!;
    const cur = points[i]!.codePointAt(0)!;
    if (cur !== prev + 1) ascending = false;
    if (cur !== prev - 1) descending = false;
  }
  return ascending || descending;
}

/** Full PIN policy: length then trivial-pattern checks. */
export function validatePin(pin: string): PinValidationResult {
  const length = checkPinLength(pin);
  if (!length.valid) return length;
  return checkTrivialPattern(pin);
}

export function assertPinPolicy(pin: string): void {
  const result = validatePin(pin);
  if (!result.valid && result.reason) {
    throw new PinPolicyError(result.reason);
  }
}
