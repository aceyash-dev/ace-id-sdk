import type { AIDTokens, AIDUser } from './types.js';

const RESERVED_CLAIMS = new Set([
  'iss', 'aud', 'exp', 'iat', 'nbf', 'sub',
  'nonce', 'at_hash', 'c_hash', 'auth_time', 'azp', 'jti',
]);

const CLAIM_MAP: Array<[string, string]> = [
  ['name', 'name'],
  ['given_name', 'givenName'],
  ['family_name', 'familyName'],
  ['middle_name', 'middleName'],
  ['nickname', 'nickname'],
  ['preferred_username', 'preferredUsername'],
  ['username', 'username'],
  ['email', 'email'],
  ['email_verified', 'emailVerified'],
  ['picture', 'picture'],
  ['locale', 'locale'],
];

export function userFromClaims(claims: Record<string, unknown>): AIDUser {
  if (typeof claims.sub !== 'string') {
    throw new TypeError('Claims are missing "sub"');
  }
  const user: AIDUser = { sub: claims.sub };
  for (const [src, dst] of CLAIM_MAP) {
    if (src in claims) (user as Record<string, unknown>)[dst] = claims[src];
  }
  for (const [k, v] of Object.entries(claims)) {
    if (!(k in user) && !RESERVED_CLAIMS.has(k)) {
      (user as Record<string, unknown>)[k] = v;
    }
  }
  return user;
}

export function normalizeTokens(raw: Record<string, unknown>): AIDTokens {
  if (typeof raw.access_token !== 'string') {
    throw new TypeError('Token response is missing "access_token"');
  }
  const tokens: AIDTokens = {
    accessToken: raw.access_token,
    tokenType: typeof raw.token_type === 'string' ? raw.token_type : 'Bearer',
  };
  if (typeof raw.id_token === 'string') tokens.idToken = raw.id_token;
  if (typeof raw.refresh_token === 'string') tokens.refreshToken = raw.refresh_token;
  if (typeof raw.scope === 'string') tokens.scope = raw.scope;
  if (typeof raw.expires_in === 'number' && Number.isFinite(raw.expires_in)) {
    tokens.expiresIn = raw.expires_in;
    tokens.expiresAt = Date.now() + raw.expires_in * 1000;
  }
  return tokens;
}