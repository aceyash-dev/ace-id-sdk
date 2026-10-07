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
) {
    val email: String? get() = claims["email"] as? String
    val name: String? get() = claims["name"] as? String
    val picture: String? get() = claims["picture"] as? String
    val username: String?
        get() = (claims["preferred_username"] as? String)?.takeIf { it.isNotBlank() }
            ?: (claims["username"] as? String)?.takeIf { it.isNotBlank() }
}

data class AidSession(
    val tokens: AidTokens,
    val user: AidUser,
)
