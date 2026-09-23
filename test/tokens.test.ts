import { describe, expect, it } from "vitest";
import {
  isTokenExpired,
  normalizeTokenResponse,
} from "../src/core/tokens.js";

describe("tokens", () => {
  it("normalizes an OAuth token response", () => {
    const tokens = normalizeTokenResponse({
      access_token: "access",
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: "refresh",
      id_token: "id",
      scope: "openid profile",
    });

    expect(tokens.accessToken).toBe("access");
    expect(tokens.tokenType).toBe("Bearer");
    expect(tokens.refreshToken).toBe("refresh");
    expect(tokens.idToken).toBe("id");
    expect(tokens.scope).toBe("openid profile");
    expect(tokens.expiresAt).toBeTypeOf("number");
  });

  it("preserves the previous refresh token when rotation is absent", () => {
    const tokens = normalizeTokenResponse(
      {
        access_token: "new-access",
        expires_in: 3600,
      },
      "old-refresh",
    );

    expect(tokens.refreshToken).toBe("old-refresh");
  });


  it("treats expires_in=0 as immediately expired", () => {
    const tokens = normalizeTokenResponse({
      access_token: "access",
      expires_in: 0,
    });

    expect(tokens.expiresIn).toBe(0);
    expect(tokens.expiresAt).toBeTypeOf("number");
    expect(isTokenExpired(tokens, 0)).toBe(true);
  });

  it("leaves expiry undefined when expires_in is missing", () => {
    const tokens = normalizeTokenResponse({
      access_token: "access",
    });

    expect(tokens.expiresIn).toBeUndefined();
    expect(tokens.expiresAt).toBeUndefined();
    expect(isTokenExpired(tokens)).toBe(false);
  });

  it("ignores a negative expires_in value", () => {
    const tokens = normalizeTokenResponse({
      access_token: "access",
      expires_in: -1,
    });

    expect(tokens.expiresIn).toBeUndefined();
    expect(tokens.expiresAt).toBeUndefined();
  });

  it("ignores a non-finite expires_in value", () => {
    const tokens = normalizeTokenResponse({
      access_token: "access",
      expires_in: Number.NaN,
    });

    expect(tokens.expiresIn).toBeUndefined();
    expect(tokens.expiresAt).toBeUndefined();
  });

  it("does not treat an expired token as valid when leeway is zero", () => {
    const tokens = {
      accessToken: "access",
      tokenType: "Bearer",
      expiresAt: Date.now() - 1,
    };

    expect(isTokenExpired(tokens, 0)).toBe(true);
  });

  it("detects an expired token", () => {
    const tokens = {
      accessToken: "access",
      tokenType: "Bearer",
      expiresAt: Date.now() - 1000,
    };

    expect(isTokenExpired(tokens)).toBe(true);
  });

  it("detects a token inside the expiry leeway", () => {
    const tokens = {
      accessToken: "access",
      tokenType: "Bearer",
      expiresAt: Date.now() + 30_000,
    };

    expect(isTokenExpired(tokens, 60)).toBe(true);
  });

  it("accepts a token outside the expiry leeway", () => {
    const tokens = {
      accessToken: "access",
      tokenType: "Bearer",
      expiresAt: Date.now() + 300_000,
    };

    expect(isTokenExpired(tokens, 60)).toBe(false);
  });
});
