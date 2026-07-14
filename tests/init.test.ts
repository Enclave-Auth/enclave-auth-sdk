import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@enclave/pqc-primitives", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@enclave/pqc-primitives")>();
  return {
    ...actual,
    runSelfTests: vi.fn(),
  };
});

import { runSelfTests } from "@enclave/pqc-primitives";
import {
  initCrypto,
  isSelfTestFailure,
  resetInitCryptoForTests,
} from "../src/init.js";

describe("initCrypto", () => {
  beforeEach(() => {
    resetInitCryptoForTests();
    vi.mocked(runSelfTests).mockReset();
  });

  it("surfaces SelfTestFailureError when CAST fails", async () => {
    const err = new Error("SelfTestFailure: forced");
    err.name = "SelfTestFailureError";
    vi.mocked(runSelfTests).mockRejectedValueOnce(err);

    await expect(initCrypto()).rejects.toSatisfy(
      (e: unknown) => isSelfTestFailure(e),
    );
    expect(runSelfTests).toHaveBeenCalledTimes(1);
  });

  it("resolves when self-tests pass", async () => {
    vi.mocked(runSelfTests).mockResolvedValueOnce(undefined);
    await expect(initCrypto()).resolves.toBeUndefined();
    expect(runSelfTests).toHaveBeenCalledTimes(1);
  });
});
