package tab.aid.sdk

data class AidTokens(
    val accessToken: String,
    val tokenType: String = "Bearer",
    val expiresAt: Long? = null,
    val refreshToken: String? = null,
    val idToken: String? = null,
    val scope: String? = null,
)

data class AidUser(
    val subject: String,
    val claims: Map<String, Any?>,
)

data class AidSession(
    val tokens: AidTokens,
    val user: AidUser,
)
