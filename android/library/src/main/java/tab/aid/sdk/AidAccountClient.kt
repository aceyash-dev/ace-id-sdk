package tab.aid.sdk

import org.json.JSONArray
import org.json.JSONObject

internal object AidAccountClient {
    @JvmOverloads
    fun fetch(
        configuration: OidcConfiguration,
        accessToken: String,
        policy: AidNetworkPolicy = AidNetworkPolicy.default(),
    ): AidUser {
        val endpoint = configuration.userInfoEndpoint
            ?: throw AidDiscoveryException("OIDC discovery document is missing userinfo_endpoint")
        val response = try {
            // UserInfo is an idempotent GET; a transient 5xx is safe to repeat.
            AidHttp.get(
                endpoint = endpoint,
                headers = mapOf(
                    "Accept" to "application/json",
                    "Authorization" to "Bearer " + accessToken,
                ),
                policy = policy,
                retryable = true,
            )
        } catch (e: AidException) {
            throw AidException("OIDC UserInfo request failed", e)
        }

        if (response.status == 401 || response.status == 403) {
            throw AidException("OIDC UserInfo rejected the access token: HTTP " + response.status)
        }
        if (!response.isSuccessful) {
            throw AidException("OIDC UserInfo request failed: HTTP " + response.status)
        }
        val value = try { JSONObject(response.body) } catch (e: Exception) {
            throw AidException("OIDC UserInfo response is not valid JSON", e)
        }
        val subject = value.optString("sub")
        if (subject.isBlank()) throw AidException("OIDC UserInfo response is missing sub")
        return AidUser(subject = subject, claims = jsonObjectToMap(value))
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
