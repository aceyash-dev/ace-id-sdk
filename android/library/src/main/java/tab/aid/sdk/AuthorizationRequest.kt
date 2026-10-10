package tab.aid.sdk

data class AuthorizationRequest(
    val url: String,
    val state: String,
    val nonce: String,
    val codeVerifier: String,
    val redirectUri: String,
)
