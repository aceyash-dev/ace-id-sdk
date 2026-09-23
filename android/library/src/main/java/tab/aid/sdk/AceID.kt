package tab.aid.sdk

import android.net.Uri

/**
 * Android entry point for ace-id-sdk.
 *
 * Network operations must not run on the Android main thread.
 */
class AceID(
    val issuer: String,
    val clientId: String,
    val redirectUri: String,
    val scope: String = "openid profile email",
) {
    private val normalizedIssuer: String = OidcDiscovery.normalizeIssuer(issuer)

    init {
        if (clientId.isBlank()) throw AidConfigurationException("clientId must not be blank")
        if (redirectUri.isBlank()) throw AidConfigurationException("redirectUri must not be blank")
        if (scope.isBlank()) throw AidConfigurationException("scope must not be blank")
    }

    fun discover(): OidcConfiguration = OidcDiscovery.fetch(normalizedIssuer)

    fun createAuthorizationRequest(
        configuration: OidcConfiguration,
    ): AuthorizationRequest {
        require(configuration.issuer == normalizedIssuer) {
            "OIDC configuration issuer does not match this client"
        }
        if (
            configuration.codeChallengeMethodsSupported.isNotEmpty() &&
            !configuration.codeChallengeMethodsSupported.contains("S256")
        ) {
            throw AidDiscoveryException("OIDC provider does not advertise PKCE S256 support")
        }

        val state = Pkce.randomString()
        val nonce = Pkce.randomString()
        val codeVerifier = Pkce.createCodeVerifier()
        val codeChallenge = Pkce.createCodeChallenge(codeVerifier)

        val url = Uri.parse(configuration.authorizationEndpoint).buildUpon()
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("client_id", clientId)
            .appendQueryParameter("redirect_uri", redirectUri)
            .appendQueryParameter("scope", scope)
            .appendQueryParameter("state", state)
            .appendQueryParameter("nonce", nonce)
            .appendQueryParameter("code_challenge", codeChallenge)
            .appendQueryParameter("code_challenge_method", "S256")
            .build()
            .toString()

        return AuthorizationRequest(url, state, nonce, codeVerifier, redirectUri)
    }
}
