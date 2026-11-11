import { userFromClaims } from './claims.js';
import { AIDAuthenticationError, AIDNetworkError, AIDProfileError } from './errors.js';
import {
  DEFAULT_MAX_RESPONSE_BYTES,
  ResponseSizeError,
  isRetryableNetworkError,
  isRetryableStatus,
  requestJson,
  type RetryPolicy,
} from './http.js';
import type { AIDUser } from './types.js';

/**
 * UserInfo (profile) retrieval.
 *
 * The ID token carries the claims the provider chose to include at sign-in; the
 * UserInfo endpoint is how an application gets the current profile, including
 * claims added after the token was issued. This is the "account profile API" the
 * SDK exposes uniformly on every platform.
 *
 * `sub` from UserInfo must match the session's subject. A mismatch means the
 * access token belongs to a different account — typically a token swap or a
 * cache mix-up — and is treated as an authentication failure rather than a
 * profile update.
 */
export interface FetchProfileOptions {
  userinfoEndpoint: string;
  accessToken: string;
  /** Subject the profile must match. */
  expectedSubject?: string;
  timeoutMs?: number;
  retry?: Partial<RetryPolicy> | false;
  maxBytes?: number;
  signal?: AbortSignal;
}

export interface ProfileResult {
  user: AIDUser;
  /** Raw claims as returned by the provider. */
  claims: Record<string, unknown>;
}

export async function fetchUserProfile(options: FetchProfileOptions): Promise<ProfileResult> {
  const { userinfoEndpoint, accessToken } = options;
  if (typeof userinfoEndpoint !== 'string' || !userinfoEndpoint) {
    throw new AIDProfileError('A userinfo_endpoint is required to fetch a profile');
  }
  if (typeof accessToken !== 'string' || !accessToken) {
    throw new AIDAuthenticationError('An access token is required to fetch a profile');
  }

  let response: Response;
  let payload: Record<string, unknown>;
  try {
    const result = await requestJson(
      userinfoEndpoint,
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
      },
      {
        ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
        // A UserInfo GET is idempotent, so transient failures may be retried.
        retry: options.retry ?? {},
        maxBytes: options.maxBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
        ...(options.signal ? { signal: options.signal } : {}),
      },
    );
    response = result.response;
    payload = result.payload;
  } catch (err) {
    if (err instanceof ResponseSizeError) {
      throw new AIDProfileError('UserInfo response exceeded the maximum accepted size', err);
    }
    if (err instanceof SyntaxError) {
      throw new AIDProfileError('UserInfo response was not valid JSON', err);
    }
    throw new AIDProfileError('UserInfo request failed', err, {
      retryable: isRetryableNetworkError(err),
    });
  }

  if (response.status === 401 || response.status === 403) {
    throw new AIDAuthenticationError(
      `UserInfo rejected the access token (HTTP ${response.status})`,
    );
  }
  if (!response.ok) {
    throw new AIDProfileError(`UserInfo request failed: HTTP ${response.status}`, undefined, {
      retryable: isRetryableStatus(response.status),
      details: { status: response.status },
    });
  }

  if (typeof payload.sub !== 'string' || !payload.sub) {
    throw new AIDProfileError('UserInfo response is missing "sub"');
  }
  if (options.expectedSubject !== undefined && payload.sub !== options.expectedSubject) {
    throw new AIDAuthenticationError('UserInfo subject does not match the current session');
  }

  let user: AIDUser;
  try {
    user = userFromClaims(payload);
  } catch (err) {
    throw new AIDProfileError('UserInfo response could not be mapped to a user', err);
  }
  return { user, claims: payload };
}

/** True when a failure is worth retrying without changing anything else. */
export function isRetryableProfileError(err: unknown): boolean {
  return err instanceof AIDProfileError && err.retryable;
}

export { AIDNetworkError };
