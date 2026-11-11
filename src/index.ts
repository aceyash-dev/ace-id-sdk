export { AID } from './browser/client.js';
export type { AIDProfileOptions, AIDRefreshOptions } from './browser/client.js';
export { MemoryStorage, SessionStorage, LocalStorage } from './browser/storage.js';
export { createCodeVerifier, createCodeChallenge } from './browser/pkce.js';
export {
  AIDError,
  AIDDiscoveryError,
  AIDCallbackError,
  AIDTokenError,
  AIDAuthenticationError,
  AIDStorageError,
  AIDNetworkError,
  AIDSessionError,
  AIDProfileError,
  aidErrorCode,
  isAIDError,
  isRetryableError,
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
export { clearJwksCache, jwksCacheSize } from './core/jwt.js';

// Session state
export { deriveSessionState } from './core/session-state.js';
export type {
  AIDSessionState,
  AIDSessionStatus,
  AIDSessionListener,
  AIDSessionStateAuthenticated,
  AIDSessionStateUnauthenticated,
  AIDSessionStateExpired,
  AIDSessionStateRefreshFailed,
} from './core/session-state.js';

// Configuration diagnostics
export { validateAIDConfig, summarizeAIDChecks } from './core/config.js';
export type { AIDConfigCheck, AIDConfigReport, AIDCheckStatus } from './core/config.js';

// Discovery caching
export { DiscoveryCache, clearDiscoveryCache } from './core/discovery.js';
export type { DiscoveryCacheOptions, OIDCDiscoveryDocument } from './core/discovery.js';

// Logging
export { createLogger, redact, redactUrl, silentLogger } from './core/logging.js';
export type { AIDLogger, AIDLogEntry, AIDLogLevel, AIDLogSink, AIDLoggingOptions } from './core/logging.js';

// Network policy
export {
  DEFAULT_RETRY_POLICY,
  isRetryableStatus,
  isRetryableNetworkError,
  retryAfterMs,
} from './core/http.js';
export type { RetryPolicy, RequestOptions } from './core/http.js';

// Profile
export { fetchUserProfile } from './core/profile.js';
export type { FetchProfileOptions, ProfileResult } from './core/profile.js';

export { createAIDFromProjectConfig } from './browser/project-config.js';
