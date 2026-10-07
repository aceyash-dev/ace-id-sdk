package tab.aid.sdk

import org.json.JSONObject

internal class AidSessionStore(
    private val storage: AidSecureStorage,
) {
    fun save(session: AidSession) {
        val tokens = JSONObject()
            .put("access_token", session.tokens.accessToken)
            .put("token_type", session.tokens.tokenType)
            .put("expires_at", session.tokens.expiresAt)
            .put("refresh_token", session.tokens.refreshToken)
            .put("id_token", session.tokens.idToken)
            .put("scope", session.tokens.scope)
        storage.put(
            "session",
            JSONObject()
                .put("tokens", tokens)
                .put("user", userToJson(session.user))
                .toString(),
        )
    }

    fun get(): AidSession? {
        val raw = storage.get("session") ?: return null
        return try {
            val value = JSONObject(raw)
            val tokens = value.getJSONObject("tokens")
            val user = userFromJson(value.getJSONObject("user"))
            AidSession(
                tokens = AidTokens(
                    accessToken = tokens.getString("access_token"),
                    tokenType = tokens.optString("token_type", "Bearer"),
                    expiresAt = tokens.optLong("expires_at", -1L).takeIf { it >= 0 },
                    refreshToken = tokens.optString("refresh_token").takeIf { it.isNotBlank() },
                    idToken = tokens.optString("id_token").takeIf { it.isNotBlank() },
                    scope = tokens.optString("scope").takeIf { it.isNotBlank() },
                ),
                user = user,
            )
        } catch (e: Exception) {
            throw AidException("Stored SDK session is invalid", e)
        }
    }

    fun clear() {
        storage.remove("session")
    }

    companion object {
        internal fun userToJson(user: AidUser): JSONObject =
            JSONObject(user.claims)
                .put("sub", user.subject)
                .put("email", user.email)
                .put("name", user.name)
                .put("picture", user.picture)
                .put("preferred_username", user.username)

        internal fun userFromJson(value: JSONObject): AidUser {
            val subject = value.optString("sub")
            if (subject.isBlank()) throw AidException("Stored SDK user is missing sub")
            return AidUser(
                subject = subject,
                claims = jsonObjectToMap(value),
            )
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
            is org.json.JSONArray -> (0 until value.length()).map { jsonValueToKotlin(value.opt(it)) }
            else -> value
        }
    }
}
