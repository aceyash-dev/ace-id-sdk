package tab.aid.sdk

import org.json.JSONObject

internal data class AidTransaction(
    val state: String,
    val nonce: String,
    val codeVerifier: String,
    val redirectUri: String,
    val createdAt: Long,
) {
    fun toJson(): String = JSONObject()
        .put("state", state)
        .put("nonce", nonce)
        .put("code_verifier", codeVerifier)
        .put("redirect_uri", redirectUri)
        .put("created_at", createdAt)
        .toString()

    companion object {
        fun fromJson(json: String): AidTransaction {
            val value = JSONObject(json)
            return AidTransaction(
                state = value.getString("state"),
                nonce = value.getString("nonce"),
                codeVerifier = value.getString("code_verifier"),
                redirectUri = value.getString("redirect_uri"),
                createdAt = value.getLong("created_at"),
            )
        }
    }
}
