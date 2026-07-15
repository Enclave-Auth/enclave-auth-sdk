import { createHash, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  MAX_LENGTH,
  MIN_LENGTH,
  checkBreached,
  checkLength,
  passwordCodePointLength,
  validatePassword,
} from "../src/password-policy.js";

function sha1Upper(password: string): string {
  return createHash("sha1").update(password, "utf8").digest("hex").toUpperCase();
}

function mockHibpFetch(body: string, ok = true): typeof fetch {
  return (async () =>
    new Response(body, {
      status: ok ? 200 : 503,
      headers: { "Content-Type": "text/plain" },
    })) as typeof fetch;
}

describe("checkLength", () => {
  it("rejects 11 code points and accepts 12", () => {
    expect(checkLength("a".repeat(11))).toEqual({
      valid: false,
      reason: "too_short",
    });
    expect(checkLength("a".repeat(MIN_LENGTH))).toEqual({ valid: true });
  });

  it("accepts 128 code points and rejects 129", () => {
    expect(checkLength("a".repeat(MAX_LENGTH))).toEqual({ valid: true });
    expect(checkLength("a".repeat(MAX_LENGTH + 1))).toEqual({
      valid: false,
      reason: "too_long",
    });
  });

  it("counts Unicode code points, not UTF-16 units or UTF-8 bytes", () => {
    // U+1F600 is one code point, two UTF-16 units, four UTF-8 bytes.
    const emoji = "😀";
    expect(emoji.length).toBe(2);
    expect(Buffer.byteLength(emoji, "utf8")).toBe(4);
    expect(passwordCodePointLength(emoji)).toBe(1);

    // 11 emoji + one ASCII = 12 code points (would be 23 UTF-16 units).
    const pass = `${"😀".repeat(11)}x`;
    expect(passwordCodePointLength(pass)).toBe(12);
    expect(pass.length).toBe(23);
    expect(checkLength(pass)).toEqual({ valid: true });

    // 11 code points of emoji alone still too short.
    expect(checkLength("😀".repeat(11))).toEqual({
      valid: false,
      reason: "too_short",
    });
  });
});

describe("checkBreached", () => {
  it('flags known-breached "password123" via HIBP range response', async () => {
    const full = sha1Upper("password123");
    const suffix = full.slice(5);
    const fetchImpl = mockHibpFetch(`${suffix}:12031938\nDEADBEEF:1\n`);
    const result = await checkBreached("password123", { fetch: fetchImpl });
    expect(result).toEqual({ breached: true });
  });

  it("returns breached: false for a high-entropy random password", async () => {
    const password = randomBytes(32).toString("base64url");
    // Range body lists other suffixes only — our hash suffix must not match.
    const fetchImpl = mockHibpFetch("0123456789ABCDEF0123456789ABCDEF012:1\n");
    const result = await checkBreached(password, { fetch: fetchImpl });
    expect(result).toEqual({ breached: false });
  });

  it("fails open with checkFailed when HIBP is unreachable", async () => {
    const fetchImpl = (async () => {
      throw new TypeError("network down");
    }) as typeof fetch;
    const result = await checkBreached("definitely-long-enough", {
      fetch: fetchImpl,
    });
    expect(result).toEqual({ breached: false, checkFailed: true });
  });

  it("fails open on non-OK HTTP status", async () => {
    const result = await checkBreached("definitely-long-enough", {
      fetch: mockHibpFetch("", false),
    });
    expect(result).toEqual({ breached: false, checkFailed: true });
  });

  it("fails open on abort/timeout", async () => {
    const fetchImpl = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ) => {
      const signal = init?.signal;
      return await new Promise<Response>((_resolve, reject) => {
        signal?.addEventListener("abort", () => {
          reject(new DOMException("Aborted", "AbortError"));
        });
      });
    }) as typeof fetch;
    const result = await checkBreached("definitely-long-enough", {
      fetch: fetchImpl,
      timeoutMs: 20,
    });
    expect(result).toEqual({ breached: false, checkFailed: true });
  });
});

describe("validatePassword", () => {
  it("fails fast on length without calling fetch", async () => {
    let called = false;
    const fetchImpl = (async () => {
      called = true;
      return new Response("", { status: 200 });
    }) as typeof fetch;
    const result = await validatePassword("short", { fetch: fetchImpl });
    expect(result).toEqual({ valid: false, reason: "too_short" });
    expect(called).toBe(false);
  });

  it("rejects breached passwords after length passes", async () => {
    // "password123" is 11 chars (fails length first); use a 12+ known pattern.
    const password = "password1234";
    const full = sha1Upper(password);
    const fetchImpl = mockHibpFetch(`${full.slice(5)}:99\n`);
    const result = await validatePassword(password, { fetch: fetchImpl });
    expect(result).toEqual({ valid: false, reason: "breached" });
  });

  it("accepts when length ok and HIBP fails open", async () => {
    const fetchImpl = (async () => {
      throw new Error("unreachable");
    }) as typeof fetch;
    const result = await validatePassword("long-enough-pw", {
      fetch: fetchImpl,
    });
    expect(result).toEqual({ valid: true, checkFailed: true });
  });
});
