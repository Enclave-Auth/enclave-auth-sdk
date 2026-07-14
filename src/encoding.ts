/**
 * Isomorphic base64url helpers (browser + Node). No Buffer / Node-only APIs.
 */

function bytesToBinaryString(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += String.fromCharCode(bytes[i]!);
  }
  return out;
}

function binaryStringToBytes(binary: string): Uint8Array {
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

/** Encode bytes as base64url (no padding). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  const b64 = btoa(bytesToBinaryString(bytes));
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

/** Decode base64url (with or without padding) to bytes. */
export function base64UrlToBytes(value: string): Uint8Array {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("base64url value must not be empty");
  }
  const padded = trimmed.replace(/-/g, "+").replace(/_/g, "/");
  const padLen = (4 - (padded.length % 4)) % 4;
  const b64 = padded + "=".repeat(padLen);
  try {
    return binaryStringToBytes(atob(b64));
  } catch {
    throw new Error("invalid base64url encoding");
  }
}

/** UTF-8 encode a string. */
export function utf8Encode(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

/** UTF-8 decode bytes. */
export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}
