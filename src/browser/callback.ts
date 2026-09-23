import { AIDCallbackError } from '../core/errors.js';

export interface CallbackParams {
  code?: string;
  state?: string;
  error?: string;
  errorDescription?: string;
}

/**
 * Ace ID returns OAuth callback parameters in the query string.
 * We do not read the fragment here; that is a deliberate contract decision.
 */
export function parseCallback(url: string): CallbackParams {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (err) {
    throw new AIDCallbackError(`Callback URL is not a valid URL: ${url}`, err);
  }
  const q = parsed.searchParams;
  return {
    code: q.get('code') ?? undefined,
    state: q.get('state') ?? undefined,
    error: q.get('error') ?? undefined,
    errorDescription: q.get('error_description') ?? undefined,
  };
}