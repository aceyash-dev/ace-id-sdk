export { AIDServer } from './client.js';
export {
  AIDError,
  AIDDiscoveryError,
  AIDTokenError,
  AIDAuthenticationError,
} from '../core/errors.js';
export type {
  AIDServerConfig,
  AIDTokens,
  AIDUser,
} from '../core/types.js';
export type { OIDCDiscoveryDocument } from '../core/discovery.js';