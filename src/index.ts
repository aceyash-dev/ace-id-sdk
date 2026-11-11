export { AID } from './browser/client.js';
export { MemoryStorage, SessionStorage, LocalStorage } from './browser/storage.js';
export { createCodeVerifier, createCodeChallenge } from './browser/pkce.js';
export {
  AIDError,
  AIDDiscoveryError,
  AIDCallbackError,
  AIDTokenError,
  AIDAuthenticationError,
} from './core/errors.js';
export type { AIDErrorCode } from './core/errors.js';
export type {
  AIDConfig,
  AIDAuthorizationOptions,
  AIDCallbackResult,
  AIDSession,
  AIDStorage,
  AIDTokens,
  AIDUser,
  AIDProjectConfig,
} from './core/types.js';
export {
  DEFAULT_UNKNOWN_EXPIRY_REFRESH_INTERVAL_MS,
  hasKnownExpiry,
  isTokenExpired,
  shouldRefreshToken,
} from './core/tokens.js';
export type { TokenRefreshPolicy } from './core/tokens.js';
export { clearJwksCache } from './core/jwt.js';

export { createAIDFromProjectConfig } from './browser/project-config.js';
