import type { AIDTokens } from "./types.js";
import { AIDAuthenticationError } from "./errors.js";

export interface TokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

/**
 * Minimum interval between refreshes that are triggered only because the token
 * endpoint did not report `expires_in`.
 *
 * `expires_in` is RECOMMENDED by RFC 6749 §5.1, not required. The SDK never
 * invents an expiry for such a token; it bounds how often it re-requests one.
 */
export const DEFAULT_UNKNOWN_EXPIRY_REFRESH_INTERVAL_MS = 60_000;

export function normalizeTokenResponse(
  response: TokenResponse,
  previousRefreshToken?: string,
  now = Date.now(),
): AIDTokens {
  if (
    !response ||
    typeof response.access_token !== "string" ||
    response.access_token.length === 0
  ) {
    throw new AIDAuthenticationError(
      "Token response did not contain a valid access_token.",
    );
  }

  const expiresIn =
    typeof response.expires_in === "number" &&
    Number.isFinite(response.expires_in) &&
    response.expires_in >= 0
      ? response.expires_in
      : undefined;

  const refreshToken =
    typeof response.refresh_token === "string" &&
    response.refresh_token.length > 0
      ? response.refresh_token
      : previousRefreshToken;

  return {
    accessToken: response.access_token,
    tokenType:
      typeof response.token_type === "string" &&
      response.token_type.length > 0
        ? response.token_type
        : "Bearer",
    expiresIn,
    // Only ever set from a reported lifetime. A token whose expiry the provider
    // did not state keeps `expiresAt` undefined; `obtainedAt` records when the
    // SDK received it so refresh throttling has a real anchor.
    expiresAt: expiresIn !== undefined ? now + expiresIn * 1000 : undefined,
    obtainedAt: now,
    refreshToken,
    idToken:
      typeof response.id_token === "string"
        ? response.id_token
        : undefined,
    scope:
      typeof response.scope === "string"
        ? response.scope
        : undefined,
  };
}

export function hasKnownExpiry(tokens: AIDTokens): boolean {
  return (
    typeof tokens.expiresAt === 'number' &&
    Number.isFinite(tokens.expiresAt) &&
    tokens.expiresAt > 0
  );
}

/**
 * Whether a token must be treated as expired.
 *
 * An unknown expiry is never treated as valid, so this returns true when the
 * provider did not state a lifetime. Callers deciding *whether to refresh* must
 * use {@link shouldRefreshToken} instead, which applies the refresh-storm guard.
 */
export function isTokenExpired(
  tokens: AIDTokens,
  leewaySeconds = 60,
  now = Date.now(),
): boolean {
  if (!hasKnownExpiry(tokens)) {
    return true;
  }

  return now >= (tokens.expiresAt as number) - leewaySeconds * 1000;
}

export interface TokenRefreshPolicy {
  /** Refresh this many seconds before the reported expiry. Defaults to 60. */
  leewaySeconds?: number;
  /**
   * Minimum interval between refreshes caused solely by an unreported expiry.
   * Defaults to {@link DEFAULT_UNKNOWN_EXPIRY_REFRESH_INTERVAL_MS}.
   */
  unknownExpiryRefreshIntervalMs?: number;
  now?: number;
}

/**
 * Decide whether the SDK should refresh before using these tokens.
 *
 * - Reported expiry: refresh inside the leeway window, exactly as before.
 * - Unreported expiry: the token is not claimed to be unexpired, but a token the
 *   SDK obtained within `unknownExpiryRefreshIntervalMs` is reused rather than
 *   re-requested. That bounds refreshes to one per interval instead of one per
 *   call, which is what previously broke refresh-token rotation under load.
 */
export function shouldRefreshToken(
  tokens: AIDTokens,
  policy: TokenRefreshPolicy = {},
): boolean {
  const now = policy.now ?? Date.now();

  if (hasKnownExpiry(tokens)) {
    return isTokenExpired(tokens, policy.leewaySeconds ?? 60, now);
  }

  const interval =
    policy.unknownExpiryRefreshIntervalMs ??
    DEFAULT_UNKNOWN_EXPIRY_REFRESH_INTERVAL_MS;
  const obtainedAt =
    typeof tokens.obtainedAt === 'number' && Number.isFinite(tokens.obtainedAt)
      ? tokens.obtainedAt
      : 0;

  // A token with no known issue time cannot be age-bounded, so refresh.
  if (obtainedAt <= 0) return true;

  return now - obtainedAt >= interval;
}
