/**
 * Sealed-cookie helpers for server-side session handling.
 *
 * A server session cookie is a capability: whoever holds it is signed in. It is
 * therefore encrypted and authenticated with AES-GCM under a key derived from
 * the application secret, never merely base64-encoded or signed-and-readable.
 * Tampering, truncation or a wrong secret all fail closed (returning `null`)
 * rather than throwing into a request handler.
 */

const VERSION = 'v1';
const AAD = 'ace-id-session-v1';
const encoder = new TextEncoder();

function subtle(): SubtleCrypto {
  const crypto = globalThis.crypto;
  if (!crypto?.subtle) {
    throw new Error('Web Crypto is unavailable; server sessions require Node 18+ or a secure context');
  }
  return crypto.subtle;
}

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const base64 = typeof btoa === 'function'
    ? btoa(binary)
    : (globalThis as unknown as { Buffer: { from(input: Uint8Array): { toString(enc: string): string } } })
      .Buffer.from(bytes).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const withPadding = padded + '='.repeat((4 - (padded.length % 4)) % 4);
  if (typeof atob === 'function') {
    const binary = atob(withPadding);
    const out = new Uint8Array(new ArrayBuffer(binary.length));
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  }
  const buffer = (globalThis as unknown as { Buffer: { from(input: string, enc: string): Uint8Array } })
    .Buffer.from(withPadding, 'base64');
  const out = new Uint8Array(new ArrayBuffer(buffer.byteLength));
  out.set(buffer);
  return out;
}

async function deriveKey(secret: string): Promise<CryptoKey> {
  if (typeof secret !== 'string' || secret.length < 16) {
    throw new Error('The session secret must be at least 16 characters');
  }
  const digest = await subtle().digest('SHA-256', encoder.encode(secret));
  return subtle().importKey('raw', digest, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export interface SealedPayloadOptions {
  /** Lifetime of the sealed value in seconds. */
  ttlSeconds: number;
  /** Injectable clock, for deterministic tests. */
  now?: () => number;
}

/** Encrypt and authenticate a JSON payload for a cookie value. */
export async function sealPayload(
  secret: string,
  payload: Record<string, unknown>,
  options: SealedPayloadOptions,
): Promise<string> {
  const now = options.now ?? Date.now;
  const expiresAt = Math.floor(now() / 1000) + Math.max(1, Math.floor(options.ttlSeconds));
  const body = JSON.stringify({ ...payload, exp: expiresAt });
  const key = await deriveKey(secret);
  const iv = new Uint8Array(new ArrayBuffer(12));
  globalThis.crypto.getRandomValues(iv);
  const ciphertext = await subtle().encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(AAD) },
    key,
    encoder.encode(body),
  );
  return `${VERSION}.${base64Url(iv)}.${base64Url(new Uint8Array(ciphertext))}`;
}

/** Decrypt a sealed cookie value. Returns null for tampered, expired or foreign values. */
export async function openPayload<T = Record<string, unknown>>(
  secret: string,
  token: string | null | undefined,
  options: { now?: () => number } = {},
): Promise<T | null> {
  if (typeof token !== 'string' || token.length === 0) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== VERSION) return null;
  const [, ivPart, dataPart] = parts;
  if (!ivPart || !dataPart) return null;

  try {
    const key = await deriveKey(secret);
    const plaintext = await subtle().decrypt(
      { name: 'AES-GCM', iv: fromBase64Url(ivPart), additionalData: encoder.encode(AAD) },
      key,
      fromBase64Url(dataPart),
    );
    const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const exp = (parsed as { exp?: unknown }).exp;
    if (typeof exp !== 'number' || !Number.isFinite(exp)) return null;
    const now = Math.floor((options.now ?? Date.now)() / 1000);
    if (exp <= now) return null;
    return parsed as T;
  } catch {
    // Wrong secret, tampering, truncation or a corrupt ciphertext all land here.
    return null;
  }
}

/** Parse a `Cookie` header into a plain map. */
export function parseCookies(header: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!name) continue;
    out[name] = decodeURIComponent(value);
  }
  return out;
}

export interface CookieOptions {
  name: string;
  value: string;
  path?: string;
  maxAgeSeconds?: number;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'Lax' | 'Strict' | 'None';
}

/** Serialise a `Set-Cookie` header value with safe defaults. */
export function serializeCookie(options: CookieOptions): string {
  const parts = [`${options.name}=${encodeURIComponent(options.value)}`];
  parts.push(`Path=${options.path ?? '/'}`);
  if (options.maxAgeSeconds !== undefined) {
    parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAgeSeconds))}`);
  }
  parts.push(`SameSite=${options.sameSite ?? 'Lax'}`);
  if (options.httpOnly !== false) parts.push('HttpOnly');
  if (options.secure !== false) parts.push('Secure');
  return parts.join('; ');
}

/** A `Set-Cookie` value that deletes the cookie. */
export function clearCookie(name: string, path = '/'): string {
  return serializeCookie({ name, value: '', path, maxAgeSeconds: 0 });
}
