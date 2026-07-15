import { describe, expect, it } from "vitest";

import {
  checkConfirmationWords,
  decodeRecoveryKeyFromDisplay,
  encodeRecoveryKeyForDisplay,
  generateRecoveryKey,
  getRecoveryKeyWords,
  pickConfirmationIndices,
  RECOVERY_KEY_WORD_COUNT,
} from "../src/amk/index.js";

describe("BIP39 recovery key display", () => {
  it("getRecoveryKeyWords returns 24 words matching encode", () => {
    const key = generateRecoveryKey();
    const joined = encodeRecoveryKeyForDisplay(key);
    const words = getRecoveryKeyWords(key);
    expect(words).toHaveLength(RECOVERY_KEY_WORD_COUNT);
    expect(words.join(" ")).toBe(joined);
    expect(Buffer.from(decodeRecoveryKeyFromDisplay(words.join(" ")))).toEqual(
      Buffer.from(key),
    );
  });

  it("pickConfirmationIndices returns distinct sorted indices in range", () => {
    for (let n = 0; n < 40; n += 1) {
      const indices = pickConfirmationIndices(3);
      expect(indices).toHaveLength(3);
      expect(new Set(indices).size).toBe(3);
      for (const i of indices) {
        expect(i).toBeGreaterThanOrEqual(0);
        expect(i).toBeLessThan(RECOVERY_KEY_WORD_COUNT);
      }
      expect([...indices].sort((a, b) => a - b)).toEqual(indices);
    }
  });

  it("checkConfirmationWords passes case-insensitively and fails mismatch", () => {
    const words = getRecoveryKeyWords(generateRecoveryKey());
    const indices = [2, 7, 19];
    const submitted: Record<number, string> = {
      2: words[2]!.toUpperCase(),
      7: `  ${words[7]}  `,
      19: words[19]!,
    };
    expect(checkConfirmationWords(words, indices, submitted)).toBe(true);

    submitted[7] = "notaword";
    expect(checkConfirmationWords(words, indices, submitted)).toBe(false);

    expect(
      checkConfirmationWords(words, indices, {
        2: words[2]!,
        7: words[7]!,
        // missing 19
      }),
    ).toBe(false);
  });
});
