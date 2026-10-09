package tab.aid.sdk

import org.json.JSONObject

internal data class AidTransaction(
    val state: String,
    val nonce: String,
    val codeVerifier: String,
    val redirectUri: String,
    val createdAt: Long,
) {
    fun hasValidTimestamp(
        nowMillis: Long = System.currentTimeMillis(),
        ttlMillis: Long = AceID.DEFAULT_TRANSACTION_TTL_MS,
        maxFutureSkewMillis: Long = AceID.MAX_TRANSACTION_FUTURE_SKEW_MS,
    ): Boolean =
        createdAt > 0L &&
            ttlMillis > 0L &&
            maxFutureSkewMillis >= 0L &&
            createdAt <= nowMillis + maxFutureSkewMillis &&
            nowMillis - createdAt <= ttlMillis

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
