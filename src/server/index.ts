export { AIDServer } from './client.js';
export { createAuthHandlers, getServerSession } from './handlers.js';
export type { AuthHandlers, ServerAuthOptions, ServerSession } from './handlers.js';
export {
  clearCookie,
  openPayload,
  parseCookies,
  sealPayload,
  serializeCookie,
} from './session.js';
export type { CookieOptions, SealedPayloadOptions } from './session.js';
export {
  AIDError,
  AIDDiscoveryError,
  AIDTokenError,
  AIDAuthenticationError,
  AIDNetworkError,
  AIDSessionError,
  AIDProfileError,
  aidErrorCode,
  isAIDError,
  isRetryableError,
} from '../core/errors.js';
export type { AIDErrorCode } from '../core/errors.js';
export type {
  AIDServerConfig,
  AIDTokens,
  AIDUser,
} from '../core/types.js';
export type { OIDCDiscoveryDocument } from '../core/discovery.js';
export { createLogger, redact } from '../core/logging.js';
export type { AIDLogger, AIDLogEntry, AIDLogSink } from '../core/logging.js';
