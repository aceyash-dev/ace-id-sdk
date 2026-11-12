import { describe, expect, it } from 'vitest';
import { AIDCallbackError, AIDError } from '../src/core/errors.js';
import {
  assertCallbackUrl,
  isSecureUrl,
  normalizeReturnTo,
  validatePostLogoutRedirect,
} from '../src/core/redirect.js';

const REDIRECT = 'https://app.example.test/auth/callback';

describe('assertCallbackUrl', () => {
  it('accepts a callback on the registered origin and path', () => {
    const url = assertCallbackUrl(`${REDIRECT}?code=abc&state=xyz`, REDIRECT);
    expect(url.searchParams.get('code')).toBe('abc');
  });

  it('rejects a callback on another origin', () => {
    expect(() => assertCallbackUrl('https://evil.example.test/auth/callback?code=a&state=s', REDIRECT))
      .toThrow(AIDCallbackError);
  });

  it('rejects a callback on another path of the same origin', () => {
    expect(() => assertCallbackUrl('https://app.example.test/other?code=a&state=s', REDIRECT))
      .toThrow(/path/i);
  });

  it('allows an extra registered origin', () => {
    expect(() => assertCallbackUrl(
      'https://admin.example.test/auth/callback?code=a&state=s',
      REDIRECT,
      { additionalOrigins: ['https://admin.example.test'] },
    )).not.toThrow();
  });

  it('rejects plain HTTP outside localhost', () => {
    expect(() => assertCallbackUrl('http://app.example.test/auth/callback?code=a&state=s', REDIRECT))
      .toThrow(/HTTPS/i);
  });

  it('rejects duplicated authorization parameters', () => {
    expect(() => assertCallbackUrl(`${REDIRECT}?code=a&code=b&state=s`, REDIRECT))
      .toThrow(/duplicate/i);
  });

  it('rejects a callback carrying redirect_uri', () => {
    expect(() => assertCallbackUrl(`${REDIRECT}?code=a&state=s&redirect_uri=https://evil.test`, REDIRECT))
      .toThrow(/redirect_uri/i);
  });

  it('rejects credentials in the callback URL', () => {
    expect(() => assertCallbackUrl('https://user:pw@app.example.test/auth/callback?code=a&state=s', REDIRECT))
      .toThrow(/credentials/i);
  });

  it('rejects a relative callback URL', () => {
    expect(() => assertCallbackUrl('/auth/callback?code=a&state=s', REDIRECT)).toThrow(AIDCallbackError);
  });
});

describe('normalizeReturnTo', () => {
  it('resolves a relative path against the redirect URI', () => {
    expect(normalizeReturnTo('/dashboard', REDIRECT)).toBe('https://app.example.test/dashboard');
  });

  it('accepts an absolute same-origin URL', () => {
    expect(normalizeReturnTo('https://app.example.test/settings?tab=security', REDIRECT))
      .toBe('https://app.example.test/settings?tab=security');
  });

  it('rejects cross-origin, protocol-relative and credentialed targets', () => {
    for (const target of [
      'https://evil.example.test/steal',
      '//evil.example.test/steal',
      'javascript:alert(1)',
      'https://user:pass@app.example.test/x',
    ]) {
      expect(() => normalizeReturnTo(target, REDIRECT)).toThrow(AIDError);
    }
  });

  it('rejects control characters', () => {
    expect(() => normalizeReturnTo('/dash\u0000board', REDIRECT)).toThrow(/control characters/i);
  });

  it('returns undefined when no target is supplied', () => {
    expect(normalizeReturnTo(undefined, REDIRECT)).toBeUndefined();
  });
});

describe('validatePostLogoutRedirect', () => {
  it('accepts a same-origin absolute URL', () => {
    expect(validatePostLogoutRedirect('https://app.example.test/goodbye', REDIRECT))
      .toBe('https://app.example.test/goodbye');
  });

  it('rejects another origin', () => {
    expect(() => validatePostLogoutRedirect('https://evil.example.test/', REDIRECT))
      .toThrow(/origin/i);
  });

  it('rejects plain HTTP outside localhost', () => {
    expect(() => validatePostLogoutRedirect('http://app.example.test/', REDIRECT))
      .toThrow(/HTTPS/i);
  });
});

describe('isSecureUrl', () => {
  it('treats HTTPS and loopback HTTP as secure', () => {
    expect(isSecureUrl(new URL('https://example.test'))).toBe(true);
    expect(isSecureUrl(new URL('http://localhost:3000'))).toBe(true);
    expect(isSecureUrl(new URL('http://127.0.0.1:3000'))).toBe(true);
    expect(isSecureUrl(new URL('http://example.test'))).toBe(false);
  });
});
