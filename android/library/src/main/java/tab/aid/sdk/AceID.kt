package tab.aid.sdk

/**
 * Android entry point for ace-id-sdk.
 *
 * Authentication functionality is implemented incrementally while preserving
 * the same OIDC/PKCE contract as the JavaScript SDK.
 */
class AceID(
    val issuer: String,
    val clientId: String,
    val redirectUri: String,
    val scope: String = "openid profile email",
) {
    init {
        require(issuer.isNotBlank()) { "issuer must not be blank" }
        require(clientId.isNotBlank()) { "clientId must not be blank" }
        require(redirectUri.isNotBlank()) { "redirectUri must not be blank" }
    }
}
