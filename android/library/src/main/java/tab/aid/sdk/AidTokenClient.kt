package tab.aid.sdk

import org.json.JSONObject
import java.net.URLEncoder

internal object AidTokenClient {
    fun exchangeCode(
        configuration: OidcConfiguration,
        clientId: String,
        code: String,
        redirectUri: String,
        codeVerifier: String,
        policy: AidNetworkPolicy = AidNetworkPolicy.default(),
    ): AidTokens {
        val body = form(
            "grant_type" to "authorization_code",
            "code" to code,
            "redirect_uri" to redirectUri,
            "client_id" to clientId,
            "code_verifier" to codeVerifier,
        )
        return post(configuration.tokenEndpoint, body, policy)
    }

    fun refresh(
        configuration: OidcConfiguration,
        clientId: String,
        refreshToken: String,
        scope: String?,
        policy: AidNetworkPolicy = AidNetworkPolicy.default(),
    ): AidTokens {
        val fields = mutableListOf(
            "grant_type" to "refresh_token",
            "refresh_token" to refreshToken,
            "client_id" to clientId,
        )
        if (!scope.isNullOrBlank()) fields += "scope" to scope
        return post(configuration.tokenEndpoint, form(*fields.toTypedArray()), policy)
    }

    private fun post(endpoint: String, body: String, policy: AidNetworkPolicy): AidTokens {
        // Never retried: an authorization code is single-use and a rotating
        // refresh token may already have been redeemed by a timed-out attempt.
        val response = try {
            AidHttp.postForm(
                endpoint = endpoint,
                body = body,
                headers = mapOf(
                    "Accept" to "application/json",
                    "Content-Type" to "application/x-www-form-urlencoded",
                ),
                policy = policy,
                retryable = false,
            )
        } catch (e: AidException) {
            throw AidException("OIDC token request failed", e)
        }

        if (!response.isSuccessful) {
            val error = runCatching {
                JSONObject(response.body).optString("error").takeIf { it.isNotBlank() }
            }.getOrNull()
            val description = runCatching {
                JSONObject(response.body).optString("error_description").takeIf { it.isNotBlank() }
            }.getOrNull()
            throw AidTokenEndpointException(
                errorCode = error,
                message = "OIDC token request failed: HTTP " + response.status +
                    (error?.let { " ($it)" } ?: "") +
                    (description?.let { " (provider description redacted)" } ?: ""),
            )
        }

        return parseTokens(response.body)
    }

    private fun parseTokens(json: String): AidTokens {
        val value = try {
            JSONObject(json)
        } catch (e: Exception) {
            throw AidException("OIDC token response is not valid JSON", e)
        }

        val accessToken = value.optString("access_token")
        if (accessToken.isBlank()) {
            throw AidException("OIDC token response is missing access_token")
        }

        val expiresIn = value.optLong("expires_in", -1L)
        val expiresAt = if (expiresIn >= 0) {
            (System.currentTimeMillis() / 1000L) + expiresIn
        } else {
            null
        }

        return AidTokens(
            accessToken = accessToken,
            tokenType = value.optString("token_type", "Bearer"),
            expiresAt = expiresAt,
            refreshToken = value.optString("refresh_token").takeIf { it.isNotBlank() },
            idToken = value.optString("id_token").takeIf { it.isNotBlank() },
            scope = value.optString("scope").takeIf { it.isNotBlank() },
        )
    }

    private fun form(vararg fields: Pair<String, String>): String =
        fields.joinToString("&") {
            URLEncoder.encode(it.first, "UTF-8") + "=" + URLEncoder.encode(it.second, "UTF-8")
        }
}
