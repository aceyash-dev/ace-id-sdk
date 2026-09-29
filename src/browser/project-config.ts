import { AID } from './client.js';
import type { AIDConfig, AIDProjectConfig } from '../core/types.js';

export function createAIDFromProjectConfig(
  config: AIDProjectConfig,
  options: Omit<AIDConfig, 'issuer' | 'clientId' | 'redirectUri' | 'scope'> = {}
): AID {
  return new AID({
    ...options,
    issuer: config.issuer,
    clientId: config.client_id,
    redirectUri: config.redirect_uri,
    scope: config.scopes.join(' '),
  });
}
