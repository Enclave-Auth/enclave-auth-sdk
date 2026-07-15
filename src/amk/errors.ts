/**
 * Generic unlock failure for every AMK method.
 *
 * Deliberately does not distinguish wrong password vs. wrong method vs.
 * corrupted blob — that distinction would be an oracle for callers.
 */
export class UnlockFailedError extends Error {
  override readonly name = "UnlockFailedError";

  constructor(message = "AMK unlock failed") {
    super(message);
  }
}
