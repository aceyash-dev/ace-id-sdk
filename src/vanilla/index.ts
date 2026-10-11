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
} from '../core/errors.js';

const AceID = {
  AID,
  MemoryStorage,
  SessionStorage,
  LocalStorage,
  createCodeVerifier,
  createCodeChallenge,
  createAIDFromProjectConfig,
  AIDError,
  AIDDiscoveryError,
  AIDCallbackError,
  AIDTokenError,
  AIDAuthenticationError,
};

export {
  AID,
  MemoryStorage,
  SessionStorage,
  LocalStorage,
  createCodeVerifier,
  createCodeChallenge,
  createAIDFromProjectConfig,
  AIDError,
  AIDDiscoveryError,
  AIDTokenError,
  AIDCallbackError,
  AIDAuthenticationError,
};
export type { AIDProjectConfig, AIDConfig, AIDAuthorizationOptions };

export default AceID;
