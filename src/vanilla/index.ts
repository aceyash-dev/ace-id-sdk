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
  AIDError,
  AIDDiscoveryError,
  AIDCallbackError,
  AIDTokenError,
  AIDAuthenticationError,
};

export default AceID;
