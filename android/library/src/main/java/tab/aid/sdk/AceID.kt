package tab.aid.sdk

import android.content.Context
import android.net.Uri
import android.os.Handler
import android.os.Looper
import androidx.browser.customtabs.CustomTabsIntent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.MessageDigest
import java.net.URI
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Native Android entry point for ace-id-sdk.
 *
 * Synchronous methods are retained for compatibility. New application code should
 * prefer the suspend APIs so all blocking network and crypto work runs on IO.
 */
class AceID @JvmOverloads constructor(
    val issuer: String,
    val clientId: String,
    val redirectUri: String,
    val scope: String = "openid profile email",
    val discoveryCacheTtlMs: Long = DEFAULT_DISCOVERY_CACHE_TTL_MS,
    val accountCacheTtlMs: Long = DEFAULT_ACCOUNT_CACHE_TTL_MS,
    val tokenLeewaySeconds: Long = DEFAULT_TOKEN_LEEWAY_SECONDS,
) {
    private val normalizedIssuer: String = OidcDiscovery.normalizeIssuer(issuer)
    private val refreshMutex = Mutex()
    private val refreshLock = Any()
    @Volatile private var activeLoginCallback: AidSessionCallback? = null
    private val accountState = MutableStateFlow<AidUser?>(null)
    private val sessionStateFlow = MutableStateFlow<AidSessionState>(AidSessionState.Unauthenticated)
    private val callbackScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    @Volatile private var memoryDiscovery: Pair<OidcConfiguration, Long>? = null

    companion object {
        const val DEFAULT_TRANSACTION_TTL_MS = 10 * 60 * 1000L
        const val MAX_TRANSACTION_FUTURE_SKEW_MS = 60 * 1000L
        const val DEFAULT_DISCOVERY_CACHE_TTL_MS = 6 * 60 * 60 * 1000L
        const val DEFAULT_ACCOUNT_CACHE_TTL_MS = 30 * 1000L
        const val DEFAULT_TOKEN_LEEWAY_SECONDS = 60L
    }

    init {
        if (clientId.isBlank()) throw AidConfigurationException("clientId must not be blank")
        if (redirectUri.isBlank()) throw AidConfigurationException("redirectUri must not be blank")
        if (scope.isBlank()) throw AidConfigurationException("scope must not be blank")
        if (discoveryCacheTtlMs <= 0) throw AidConfigurationException("discoveryCacheTtlMs must be > 0")
        if (accountCacheTtlMs < 0) throw AidConfigurationException("accountCacheTtlMs must not be negative")
        if (tokenLeewaySeconds < 0) throw AidConfigurationException("tokenLeewaySeconds must not be negative")
        validateRedirectUri(redirectUri)
    }

    fun discover(): OidcConfiguration {
        val now = System.currentTimeMillis()
        memoryDiscovery?.takeIf { it.second > now }?.let { return it.first }
        val configuration = OidcDiscovery.fetch(normalizedIssuer)
        memoryDiscovery = configuration to (now + discoveryCacheTtlMs)
        return configuration
    }

    fun discover(context: Context, forceRefresh: Boolean = false): OidcConfiguration =
        AidDiscoveryCache(context, normalizedIssuer, clientId, discoveryCacheTtlMs).get(forceRefresh)

    fun createAuthorizationRequest(configuration: OidcConfiguration): AuthorizationRequest {
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

    @JvmOverloads
    fun startAuthorization(
        context: Context,
        configuration: OidcConfiguration = discover(context),
    ): AuthorizationRequest {
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
        CustomTabsIntent.Builder().build().launchUrl(context, Uri.parse(request.url))
        return request
    }

    fun login(context: Context, callback: AidSessionCallback) {
        if (activeLoginCallback != null) {
            dispatchCallback(callback) { onError(AidException("An Ace ID login is already in progress")) }
            return
        }
        activeLoginCallback = callback
        callbackScope.launch {
            try {
                startAuthorizationAsync(context)
            } catch (e: Throwable) {
                if (activeLoginCallback === callback) activeLoginCallback = null
                dispatchCallback(callback) { onError(e) }
            }
        }
    }

    private suspend fun startAuthorizationAsync(context: Context): AuthorizationRequest {
        val configuration = withContext(Dispatchers.IO) { discover(context) }
        val request = createAuthorizationRequest(configuration)
        withContext(Dispatchers.IO) {
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
        }
        withContext(kotlinx.coroutines.Dispatchers.Main.immediate) {
            CustomTabsIntent.Builder().build().launchUrl(context, Uri.parse(request.url))
        }
        return request
    }

    suspend fun handleCallbackAsync(context: Context, callbackUri: Uri): AidSession =
        withContext(Dispatchers.IO) { handleCallback(context, callbackUri) }

    suspend fun login(context: Context): AidSession =
        suspendCancellableCoroutine { continuation ->
            val callback = object : AidSessionCallback {
                override fun onSuccess(session: AidSession) {
                    if (continuation.isActive) continuation.resume(session)
                }

                override fun onError(error: Throwable) {
                    if (continuation.isActive) continuation.resumeWithException(error)
                }
            }
            login(context, callback)
            continuation.invokeOnCancellation { if (activeLoginCallback === callback) activeLoginCallback = null }
        }

    fun handleCallback(context: Context, callbackUri: Uri): AidSession {
        val storage = AidSecureStorage(context, normalizedIssuer, clientId)
        val state = callbackUri.getQueryParameter("state")
            ?: throw AidException("Authorization callback is missing state")

        val transactionJson = storage.get("transaction")
            ?: throw AidException("No pending authorization transaction")
        val transaction = try {
            AidTransaction.fromJson(transactionJson)
        } catch (error: Exception) {
            // A malformed local transaction cannot be safely matched to this callback.
            storage.remove("transaction")
            throw AidException("Stored authorization transaction is invalid", error)
        }

        if (!MessageDigest.isEqual(
                transaction.state.toByteArray(Charsets.UTF_8),
                state.toByteArray(Charsets.UTF_8),
            )
        ) {
            // Unmatched callbacks must not cancel a legitimate login in progress.
            throw AidException("Authorization state does not match the pending transaction")
        }

        fun failMatchedCallback(error: Throwable): Nothing {
            storage.remove("transaction")
            notifyLoginFailure(error)
            throw error
        }

        if (!transaction.hasValidTimestamp()) {
            failMatchedCallback(AidException("Authorization transaction has an invalid timestamp or has expired"))
        }

        val providerError = callbackUri.getQueryParameter("error")
        if (!providerError.isNullOrBlank()) {
            // Do not echo the provider's free-form error_description into SDK messages.
            failMatchedCallback(AidException("OIDC authorization failed: $providerError"))
        }

        val code = callbackUri.getQueryParameter("code")
            ?: failMatchedCallback(AidException("Authorization callback is missing code"))

        if (callbackUri.getQueryParameter("redirect_uri") != null) {
            failMatchedCallback(AidException("Unexpected redirect_uri parameter in authorization callback"))
        }

        if (transaction.redirectUri != redirectUri) {
            failMatchedCallback(AidException("Authorization transaction redirect URI does not match this client"))
        }

        // Consume the transaction before exchanging the code. This prevents replay,
        // including when the token endpoint or ID-token validation fails.
        storage.remove("transaction")
        try {
            val configuration = discover(context)
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
            accountState.value = user
            sessionStateFlow.value = AidSessionState.Authenticated(user)
            notifyLoginSuccess(session)
            return session
        } catch (error: Throwable) {
            notifyLoginFailure(error)
            throw error
        }
    }

    fun getSession(context: Context): AidSession? =
        AidSessionStore(AidSecureStorage(context, normalizedIssuer, clientId)).get()

    @JvmOverloads
    fun isAuthenticated(
        context: Context,
        leewaySeconds: Long = tokenLeewaySeconds,
    ): Boolean {
        val session = getSession(context) ?: return false
        if (leewaySeconds < 0) return false
        val expiresAt = session.tokens.expiresAt ?: return false
        return expiresAt > 0L && expiresAt > (System.currentTimeMillis() / 1000L) + leewaySeconds
    }

    fun getUser(context: Context): AidUser? = getSession(context)?.user.also { accountState.value = it }

    fun getAccessToken(context: Context): String? = getSession(context)?.tokens?.accessToken

    @JvmOverloads
    fun getValidAccessToken(
        context: Context,
        leewaySeconds: Long = tokenLeewaySeconds,
    ): String? = synchronized(refreshLock) {
        require(leewaySeconds >= 0) { "leewaySeconds must not be negative" }

        val storage = AidSecureStorage(context, normalizedIssuer, clientId)
        val store = AidSessionStore(storage)
        val session = store.get() ?: return@synchronized null
        val expiresAt = session.tokens.expiresAt
        val now = System.currentTimeMillis() / 1000L

        if (expiresAt != null && expiresAt > 0L && expiresAt > now + leewaySeconds) {
            return@synchronized session.tokens.accessToken
        }

        if (expiresAt == null && session.tokens.refreshToken.isNullOrBlank()) {
            // expires_in is optional in OAuth. Unknown expiry alone is not proof that
            // this access token has expired, so do not destroy a usable session.
            return@synchronized session.tokens.accessToken
        }

        if (session.tokens.refreshToken.isNullOrBlank()) {
            store.clear()
            accountState.value = null
            sessionStateFlow.value = AidSessionState.Unauthenticated
            return@synchronized null
        }

        // All sync and suspend entry points share this lock so a rotating refresh
        // token cannot be submitted concurrently by two callers.
        try {
            refreshSession(context, session, store, storage).tokens.accessToken
        } catch (error: AidTokenEndpointException) {
            if (error.errorCode == "invalid_grant") {
                store.clear()
                accountState.value = null
                sessionStateFlow.value = AidSessionState.Unauthenticated
            }
            throw error
        }
    }

    private fun refreshSession(
        context: Context,
        session: AidSession,
        store: AidSessionStore,
        storage: AidSecureStorage,
    ): AidSession {
        val refreshToken = session.tokens.refreshToken
            ?: throw AidException("Access token has expired and no refresh token is available")
        val configuration = discover(context)
        if (
            configuration.grantTypesSupported.isNotEmpty() &&
            !configuration.grantTypesSupported.contains("refresh_token")
        ) {
            throw AidDiscoveryException("OIDC provider does not advertise refresh_token grant support")
        }

        val refreshed = AidTokenClient.refresh(
            configuration = configuration,
            clientId = clientId,
            refreshToken = refreshToken,
            scope = session.tokens.scope ?: scope,
        )

        var user = session.user
        refreshed.idToken?.let { token ->
            val refreshedUser = AidJwtVerifier.verify(token, configuration, clientId)
            if (refreshedUser.subject != session.user.subject) {
                throw AidException("Refreshed ID token subject does not match the current session")
            }
            user = refreshedUser
        }

        val updated = AidSession(
            tokens = refreshed.copy(
                refreshToken = refreshed.refreshToken ?: refreshToken,
                idToken = refreshed.idToken ?: session.tokens.idToken,
            ),
            user = user,
        )
        store.save(updated)
        accountState.value = user
        sessionStateFlow.value = AidSessionState.Authenticated(user)
        return updated
    }

    suspend fun getValidAccessTokenAsync(
        context: Context,
        leewaySeconds: Long = tokenLeewaySeconds,
    ): String? = withContext(Dispatchers.IO) {
        refreshMutex.withLock {
            // Re-read the latest persisted session after acquiring the mutex so a
            // concurrent caller observes the rotated token rather than refreshing
            // with a stale refresh token.
            getValidAccessToken(context, leewaySeconds)
        }
    }

    suspend fun getAccount(context: Context, cache: Boolean = true): AidUser? =
        withContext(Dispatchers.IO) {
            val token = getValidAccessTokenAsync(context) ?: return@withContext null
            val session = getSession(context) ?: return@withContext null
            val storage = AidSecureStorage(context, normalizedIssuer, clientId)

            if (cache) {
                readAccountCache(storage, session.user.subject)?.let {
                    accountState.value = it
                    sessionStateFlow.value = AidSessionState.Authenticated(it)
                    return@withContext it
                }
            }

            val account = AidAccountClient.fetch(discover(context), token)
            if (account.subject != session.user.subject) {
                throw AidException("UserInfo subject does not match the current session")
            }
            writeAccountCache(storage, account)
            accountState.value = account
            sessionStateFlow.value = AidSessionState.Authenticated(account)
            account
        }

    suspend fun restoreSession(context: Context): AidSessionState {
        val session = withContext(Dispatchers.IO) { getSession(context) }
            ?: return AidSessionState.Unauthenticated.also { sessionStateFlow.value = it }
        return runCatching {
            val token = getValidAccessTokenAsync(context)
            if (token == null) AidSessionState.Unauthenticated
            else AidSessionState.Authenticated(getUser(context) ?: session.user)
        }.getOrElse { AidSessionState.Expired }.also { sessionStateFlow.value = it }
    }

    val account: StateFlow<AidUser?> get() = accountState
    val sessionState: StateFlow<AidSessionState> get() = sessionStateFlow

    suspend fun <T> withAccessToken(
        context: Context,
        block: suspend (String) -> T,
    ): T {
        val token = getValidAccessTokenAsync(context)
            ?: throw AidException("No authenticated Ace ID session")
        return block(token)
    }

    suspend fun validateConfiguration(): AidConfigurationReport =
        withContext(Dispatchers.IO) {
            val checks = mutableListOf<AidConfigurationCheck>()
            checks += AidConfigurationCheck("HTTPS issuer", issuer.startsWith("https://") || isLocalhostIssuer(), issuer)
            checks += AidConfigurationCheck("Redirect URI", runCatching { validateRedirectUri(redirectUri); true }.getOrDefault(false), redirectUri)
            val discovery = runCatching { discoverWithoutContext() }
            discovery.fold(
                onSuccess = { configuration ->
                    checks += AidConfigurationCheck("OIDC discovery", true, "Discovery succeeded")
                    checks += AidConfigurationCheck("Authorization endpoint", configuration.authorizationEndpoint.isNotBlank(), configuration.authorizationEndpoint)
                    checks += AidConfigurationCheck("Token endpoint", configuration.tokenEndpoint.isNotBlank(), configuration.tokenEndpoint)
                    checks += AidConfigurationCheck("UserInfo endpoint", !configuration.userInfoEndpoint.isNullOrBlank(), configuration.userInfoEndpoint ?: "missing")
                    checks += AidConfigurationCheck("JWKS URI", !configuration.jwksUri.isNullOrBlank(), configuration.jwksUri ?: "missing")
                    checks += AidConfigurationCheck("PKCE S256", configuration.codeChallengeMethodsSupported.isEmpty() || configuration.codeChallengeMethodsSupported.contains("S256"), "S256")
                },
                onFailure = { error ->
                    checks += AidConfigurationCheck("OIDC discovery", false, error.message ?: "Discovery failed")
                },
            )
            AidConfigurationReport(checks)
        }

    private fun discoverWithoutContext(): OidcConfiguration = discover()

    fun signOut(context: Context) {
        val storage = AidSecureStorage(context, normalizedIssuer, clientId)
        storage.remove("session")
        storage.remove("transaction")
        storage.remove("account")
        accountState.value = null
        sessionStateFlow.value = AidSessionState.Unauthenticated
    }

    private fun notifyLoginSuccess(session: AidSession) {
        val callback = activeLoginCallback ?: return
        activeLoginCallback = null
        dispatchCallback(callback) { onSuccess(session) }
    }

    private fun notifyLoginFailure(error: Throwable) {
        val callback = activeLoginCallback ?: return
        activeLoginCallback = null
        dispatchCallback(callback) { onError(error) }
    }

    private fun dispatchCallback(callback: AidSessionCallback, block: AidSessionCallback.() -> Unit) {
        Handler(Looper.getMainLooper()).post { callback.block() }
    }

    private fun readAccountCache(storage: AidSecureStorage, expectedSubject: String): AidUser? {
        val raw = storage.get("account") ?: return null
        return runCatching {
            val value = org.json.JSONObject(raw)
            if (value.getLong("expires_at") <= System.currentTimeMillis()) return null
            val user = AidSessionStore.userFromJson(value.getJSONObject("user"))
            if (user.subject != expectedSubject) null else user
        }.getOrNull()
    }

    private fun writeAccountCache(storage: AidSecureStorage, user: AidUser) {
        if (accountCacheTtlMs == 0L) return
        val value = org.json.JSONObject()
            .put("expires_at", System.currentTimeMillis() + accountCacheTtlMs)
            .put("user", AidSessionStore.userToJson(user))
        storage.put("account", value.toString())
    }

    private fun validateRedirectUri(value: String) {
        val uri = try { URI(value) } catch (e: Exception) {
            throw AidConfigurationException("redirectUri is not a valid URI")
        }
        if (uri.fragment != null) throw AidConfigurationException("redirectUri must not contain a fragment")
        if (uri.scheme.isNullOrBlank()) throw AidConfigurationException("redirectUri must include a scheme")
        if (uri.scheme == "https" && uri.host.isNullOrBlank()) {
            throw AidConfigurationException("HTTPS redirectUri must include a host")
        }
        if (uri.scheme == "http" && uri.host != "localhost" && uri.host != "127.0.0.1") {
            throw AidConfigurationException("HTTP redirectUri is only allowed for localhost development")
        }
    }

    private fun isLocalhostIssuer(): Boolean =
        runCatching {
            val uri = URI(issuer)
            uri.host == "localhost" || uri.host == "127.0.0.1"
        }.getOrDefault(false)

}

interface AidSessionCallback {
    fun onSuccess(session: AidSession)
    fun onError(error: Throwable)
}
