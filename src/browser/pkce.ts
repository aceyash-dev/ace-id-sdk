import { base64UrlEncode } from '../core/base64url.js';

const VERIFIER_MIN = 43;
const VERIFIER_MAX = 128;

function getCrypto(): Crypto {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error(
      'Web Crypto API is not available. Ensure the SDK runs in a secure context (HTTPS or localhost).',
    );
  }
  return c;
}

export function randomString(byteLength = 32): string {
  if (byteLength < 16) throw new RangeError('byteLength must be >= 16');
  const bytes = new Uint8Array(byteLength);
  getCrypto().getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

/**
 * RFC 7636 §4.1 code_verifier.
 * 32 bytes of CSPRNG output -> 43 base64url chars, within the 43..128 range.
 */
export function createCodeVerifier(byteLength = 32): string {
  if (byteLength < 32 || byteLength > 96) {
    throw new RangeError('byteLength must be between 32 and 96 bytes');
  }
  const bytes = new Uint8Array(byteLength);
  getCrypto().getRandomValues(bytes);
  const verifier = base64UrlEncode(bytes);
  if (verifier.length < VERIFIER_MIN || verifier.length > VERIFIER_MAX) {
    throw new Error('Internal error: generated code_verifier length out of RFC 7636 range');
  }
  return verifier;
}

/**
 * RFC 7636 §4.2 S256 code_challenge = BASE64URL(SHA256(ASCII(code_verifier))).
 * Only S256 is produced. No plain fallback exists.
 */
export async function createCodeChallenge(verifier: string): Promise<string> {
  if (
    typeof verifier !== 'string' ||
    verifier.length < VERIFIER_MIN ||
    verifier.length > VERIFIER_MAX
  ) {
    throw new RangeError('code_verifier must be between 43 and 128 characters');
  }
  const data = new TextEncoder().encode(verifier);
  const digest = await getCrypto().subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(digest));
}