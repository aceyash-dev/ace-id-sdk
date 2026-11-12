import { AID } from '../browser/client.js';
import {
  MemoryStorage,
  SessionStorage,
  LocalStorage,
} from '../browser/storage.js';
import {
  createCodeVerifier,
  createCodeChallenge,
} from '../browser/pkce.js';
import { createAIDFromProjectConfig } from '../browser/project-config.js';
import type { AIDProjectConfig, AIDConfig, AIDAuthorizationOptions } from '../core/types.js';
import {
  AIDError,
  AIDDiscoveryError,
  AIDCallbackError,
  AIDTokenError,
  AIDAuthenticationError,
  AIDNetworkError,
  AIDProfileError,
  AIDStorageError,
  AIDSessionError,
  aidErrorCode,
  isAIDError,
  isRetryableError,
} from '../core/errors.js';
import { deriveSessionState } from '../core/session-state.js';
import { validateAIDConfig } from '../core/config.js';
import { createLogger, redact } from '../core/logging.js';
import { isRetryableStatus, retryAfterMs } from '../core/http.js';

/**
 * Script-tag build.
 *
 * The IIFE exposes the same surface as the ESM entry point so a page that cannot
 * use a bundler still gets session state, configuration diagnostics and the
 * redacting logger, not just the client.
 */
const AceID = {
  AID,
  MemoryStorage,
  SessionStorage,
  LocalStorage,
  createCodeVerifier,
  createCodeChallenge,
  createAIDFromProjectConfig,
  deriveSessionState,
  validateAIDConfig,
  createLogger,
  redact,
  isRetryableStatus,
  retryAfterMs,
  aidErrorCode,
  isAIDError,
  isRetryableError,
  AIDError,
  AIDDiscoveryError,
  AIDCallbackError,
  AIDTokenError,
  AIDAuthenticationError,
  AIDNetworkError,
  AIDProfileError,
  AIDStorageError,
  AIDSessionError,
};

export {
  AID,
  MemoryStorage,
  SessionStorage,
  LocalStorage,
  createCodeVerifier,
  createCodeChallenge,
  createAIDFromProjectConfig,
  deriveSessionState,
  validateAIDConfig,
  createLogger,
  redact,
  aidErrorCode,
  isAIDError,
  isRetryableError,
  AIDError,
  AIDDiscoveryError,
  AIDTokenError,
  AIDCallbackError,
  AIDAuthenticationError,
  AIDNetworkError,
  AIDProfileError,
  AIDStorageError,
  AIDSessionError,
};
export type { AIDProjectConfig, AIDConfig, AIDAuthorizationOptions };

export default AceID;
