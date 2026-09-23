package tab.aid.sdk

import android.content.Context
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import java.security.MessageDigest

/**
 * Android entry point for ace-id-sdk.
 *
 * Network and cryptographic operations are synchronous and must not run on
 * the Android main thread.
 */
class AceID(
    val issuer: String,
    val clientId: String,
    val redirectUri: String,
    val scope: String = "openid profile email",
) {
    private val normalizedIssuer: String = OidcDiscovery.normalizeIssuer(issuer)

    companion object {
        const val DEFAULT_TRANSACTION_TTL_MS = 10 * 60 * 1000L
        const val DEFAULT_TOKEN_LEEWAY_SECONDS = 60L
    }

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

    /**
     * Stores the PKCE transaction and opens the provider in an Android Custom Tab.
     *
     * The application must register [redirectUri] and pass the resulting callback
     * URI to [handleCallback].
     */
    fun startAuthorization(
        context: Context,
        configuration: OidcConfiguration = discover(),
        transactionTtlMs: Long = DEFAULT_TRANSACTION_TTL_MS,
    ): AuthorizationRequest {
        require(transactionTtlMs > 0) { "transactionTtlMs must be positive" }

        val request = createAuthorizationRequest(configuration)
        AidSecureStorage(context, normalizedIssuer, clientId).put(
            "transaction",
            AidTransaction(
                state = request.state,
                nonce = request.nonce,
                codeVerifier = request.codeVerifier,
                redirectUri = request.redirectUri,
                createdAt = System.currentTimeMillis(),
            ).toJson(),
        )

        CustomTabsIntent.Builder()
            .build()
            .launchUrl(context, Uri.parse(request.url))

        return request
    }

    /**
     * Validates the authorization response, exchanges the code, verifies the
     * ID token, and persists the authenticated session.
     */
    fun handleCallback(
        context: Context,
        callbackUri: Uri,
    ): AidSession {
        val error = callbackUri.getQueryParameter("error")
        if (!error.isNullOrBlank()) {
            val description = callbackUri.getQueryParameter("error_description")
            throw AidException(
                "OIDC authorization failed: $error" +
                    (description?.let { ": $it" } ?: ""),
            )
        }

        val code = callbackUri.getQueryParameter("code")
            ?: throw AidException("Authorization callback is missing code")
        val state = callbackUri.getQueryParameter("state")
            ?: throw AidException("Authorization callback is missing state")

        val storage = AidSecureStorage(context, normalizedIssuer, clientId)
        val transactionJson = storage.get("transaction")
            ?: throw AidException("No pending authorization transaction")

        val transaction = try {
            AidTransaction.fromJson(transactionJson)
        } catch (e: Exception) {
            storage.remove("transaction")
            throw AidException("Stored authorization transaction is invalid", e)
        }

        if (System.currentTimeMillis() - transaction.createdAt > DEFAULT_TRANSACTION_TTL_MS) {
            storage.remove("transaction")
            throw AidException("Authorization transaction has expired")
        }

        if (!MessageDigest.isEqual(
                transaction.state.toByteArray(Charsets.UTF_8),
                state.toByteArray(Charsets.UTF_8),
            )
        ) {
            throw AidException("Authorization state does not match the pending transaction")
        }

        if (callbackUri.getQueryParameter("redirect_uri") != null) {
            throw AidException("Unexpected redirect_uri parameter in authorization callback")
        }

        val configuration = discover()
        if (transaction.redirectUri != redirectUri) {
            throw AidException("Authorization transaction redirect URI does not match this client")
        }

        val tokens = AidTokenClient.exchangeCode(
            configuration = configuration,
            clientId = clientId,
            code = code,
            redirectUri = transaction.redirectUri,
            codeVerifier = transaction.codeVerifier,
        )

        val idToken = tokens.idToken
            ?: throw AidException("OIDC token response is missing id_token")

        val user = AidJwtVerifier.verify(
            jwt = idToken,
            configuration = configuration,
            clientId = clientId,
            nonce = transaction.nonce,
        )

        val session = AidSession(tokens = tokens, user = user)
        AidSessionStore(storage).save(session)
        storage.remove("transaction")
        return session
    }

    fun getSession(context: Context): AidSession? =
        AidSessionStore(AidSecureStorage(context, normalizedIssuer, clientId)).get()

    fun isAuthenticated(
        context: Context,
        leewaySeconds: Long = DEFAULT_TOKEN_LEEWAY_SECONDS,
    ): Boolean {
        val session = getSession(context) ?: return false
        val expiresAt = session.tokens.expiresAt ?: return true
        return expiresAt > (System.currentTimeMillis() / 1000L) + leewaySeconds
    }

    fun getUser(context: Context): AidUser? = getSession(context)?.user

    fun getAccessToken(context: Context): String? = getSession(context)?.tokens?.accessToken

    fun signOut(context: Context) {
        val storage = AidSecureStorage(context, normalizedIssuer, clientId)
        storage.remove("session")
        storage.remove("transaction")
    }
}
