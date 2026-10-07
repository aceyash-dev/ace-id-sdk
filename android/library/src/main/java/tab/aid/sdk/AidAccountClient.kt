package tab.aid.sdk

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI

internal object AidAccountClient {
    fun fetch(
        configuration: OidcConfiguration,
        accessToken: String,
    ): AidUser {
        val endpoint = configuration.userInfoEndpoint
            ?: throw AidDiscoveryException("OIDC discovery document is missing userinfo_endpoint")

        val connection = try {
            URI(endpoint).toURL().openConnection() as HttpURLConnection
        } catch (e: Exception) {
            throw AidException("Failed to open OIDC UserInfo endpoint", e)
        }

        try {
            connection.requestMethod = "GET"
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.setRequestProperty("Accept", "application/json")
            connection.setRequestProperty("Authorization", "Bearer $accessToken")
            val responseCode = connection.responseCode
            if (responseCode !in 200..299) {
                throw AidException("OIDC UserInfo request failed: HTTP $responseCode")
            }
            val json = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            val value = try { JSONObject(json) } catch (e: Exception) {
                throw AidException("OIDC UserInfo response is not valid JSON", e)
            }
            val subject = value.optString("sub")
            if (subject.isBlank()) throw AidException("OIDC UserInfo response is missing sub")
            return AidUser(
                subject = subject,
                email = value.optString("email").takeIf { it.isNotBlank() },
                name = value.optString("name").takeIf { it.isNotBlank() },
                picture = value.optString("picture").takeIf { it.isNotBlank() },
                username = value.optString("preferred_username")
                    .takeIf { it.isNotBlank() }
                    ?: value.optString("username").takeIf { it.isNotBlank() },
                claims = jsonObjectToMap(value),
            )
        } catch (e: AidException) {
            throw e
        } catch (e: Exception) {
            throw AidException("OIDC UserInfo request failed", e)
        } finally {
            connection.disconnect()
        }
    }

    private fun jsonObjectToMap(value: JSONObject): Map<String, Any?> {
        val result = linkedMapOf<String, Any?>()
        val iterator = value.keys()
        while (iterator.hasNext()) {
            val key = iterator.next()
            result[key] = jsonValueToKotlin(value.opt(key))
        }
        return result
    }

    private fun jsonValueToKotlin(value: Any?): Any? = when (value) {
        null, JSONObject.NULL -> null
        is JSONObject -> jsonObjectToMap(value)
        is JSONArray -> (0 until value.length()).map { jsonValueToKotlin(value.opt(it)) }
        else -> value
    }
}
