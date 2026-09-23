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

export function normalizeTokenResponse(
  response: TokenResponse,
  previousRefreshToken?: string,
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
    expiresAt:
      expiresIn !== undefined
        ? Date.now() + expiresIn * 1000
        : undefined,
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

export function isTokenExpired(
  tokens: AIDTokens,
  leewaySeconds = 60,
): boolean {
  if (tokens.expiresAt === undefined) {
    return false;
  }

  return Date.now() >= tokens.expiresAt - leewaySeconds * 1000;
}
