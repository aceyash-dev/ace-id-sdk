package tab.aid.sdk

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder

internal object AidTokenClient {
    fun exchangeCode(
        configuration: OidcConfiguration,
        clientId: String,
        code: String,
        redirectUri: String,
        codeVerifier: String,
    ): AidTokens {
        val body = form(
            "grant_type" to "authorization_code",
            "code" to code,
            "redirect_uri" to redirectUri,
            "client_id" to clientId,
            "code_verifier" to codeVerifier,
        )
        return post(configuration.tokenEndpoint, body)
    }

    fun refresh(
        configuration: OidcConfiguration,
        clientId: String,
        refreshToken: String,
        scope: String?,
    ): AidTokens {
        val fields = mutableListOf(
            "grant_type" to "refresh_token",
            "refresh_token" to refreshToken,
            "client_id" to clientId,
        )
        if (!scope.isNullOrBlank()) fields += "scope" to scope
        return post(configuration.tokenEndpoint, form(*fields.toTypedArray()))
    }

    private fun post(endpoint: String, body: String): AidTokens {
        val connection = try {
            URI(endpoint).toURL().openConnection() as HttpURLConnection
        } catch (e: Exception) {
            throw AidException("Failed to open OIDC token endpoint", e)
        }

        try {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }

            val responseCode = connection.responseCode
            val stream = if (responseCode in 200..299) {
                connection.inputStream
            } else {
                connection.errorStream
            }
            val response = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()

            if (responseCode !in 200..299) {
                val error = runCatching {
                    JSONObject(response).optString("error").takeIf { it.isNotBlank() }
                }.getOrNull()
                val description = runCatching {
                    JSONObject(response).optString("error_description").takeIf { it.isNotBlank() }
                }.getOrNull()
                throw AidException(
                    "OIDC token request failed: HTTP $responseCode" +
                        (error?.let { " ($it)" } ?: "") +
                        (description?.let { ": $it" } ?: ""),
                )
            }

            return parseTokens(response)
        } catch (e: AidException) {
            throw e
        } catch (e: Exception) {
            throw AidException("OIDC token request failed", e)
        } finally {
            connection.disconnect()
        }
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
