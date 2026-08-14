import { describe, expect, it } from "vitest";
import {
  ExpiredTokenError,
  InvalidSignatureError,
  generateIdentityKeyPair,
  getLastUsageRecord,
  initCrypto,
  mintSessionToken,
  verifySessionToken,
  type SessionClaims,
} from "../src/index.js";

describe("session token mint/verify", () => {
  it("round-trips a session token", async () => {
    await initCrypto();
    const service = await generateIdentityKeyPair();
    const now = Math.floor(Date.now() / 1000);
    const claims: SessionClaims = {
      sub: "user-001",
      aud: "enclave-sign-api",
      iat: now,
      exp: now + 3600,
      jti: "jti-abc",
    };

    const token = await mintSessionToken(service.secretKeySeed, claims);
    expect(token.split(".")).toHaveLength(2);
    expect(getLastUsageRecord()?.algorithm).toBe("ML-DSA-87");

    const verified = await verifySessionToken(service.publicKey, token, now);
    expect(verified).toEqual(claims);
  });

  it("rejects expired tokens", async () => {
    await initCrypto();
    const service = await generateIdentityKeyPair();
    const claims: SessionClaims = {
      sub: "user-001",
      aud: "enclave-sign-api",
      iat: 1_700_000_000,
      exp: 1_700_000_100,
      jti: "jti-expired",
    };
    const token = await mintSessionToken(service.secretKeySeed, claims);
    await expect(
      verifySessionToken(service.publicKey, token, 1_700_000_100),
    ).rejects.toBeInstanceOf(ExpiredTokenError);
  });

  it("rejects tampered signatures", async () => {
    await initCrypto();
    const service = await generateIdentityKeyPair();
    const now = Math.floor(Date.now() / 1000);
    const token = await mintSessionToken(service.secretKeySeed, {
      sub: "user-001",
      aud: "enclave-sign-api",
      iat: now,
      exp: now + 60,
      jti: "jti-tamper",
    });
    const [payload, sig] = token.split(".");
    const flipped = `${payload}.${sig!.slice(0, -4)}AAAA`;
    await expect(
      verifySessionToken(service.publicKey, flipped, now),
    ).rejects.toBeInstanceOf(InvalidSignatureError);
  });
});

describe("fetchAuthServicePublicKey", () => {
  it("forwards extra headers for well-known publishable-key auth", async () => {
    const { encodePublicKey, fetchAuthServicePublicKey, generateIdentityKeyPair, initCrypto } =
      await import("../src/index.js");
    await initCrypto();
    const service = await generateIdentityKeyPair();
    const publicKey = encodePublicKey(service.publicKey);
    const seen: Record<string, string> = {};
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (_input, init) => {
      const headers = new Headers(init?.headers);
      headers.forEach((value, key) => {
        seen[key.toLowerCase()] = value;
      });
      return new Response(
        JSON.stringify({ publicKey, keyId: "auth-v1" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    };
    try {
      const result = await fetchAuthServicePublicKey(
        "https://auth.example/.well-known/enclave-auth",
        { headers: { "X-Enclave-Publishable-Key": "pk_dev_test" } },
      );
      expect(seen.accept).toBe("application/json");
      expect(seen["x-enclave-publishable-key"]).toBe("pk_dev_test");
      expect(result.keyId).toBe("auth-v1");
      expect(result.publicKey).toEqual(service.publicKey);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
