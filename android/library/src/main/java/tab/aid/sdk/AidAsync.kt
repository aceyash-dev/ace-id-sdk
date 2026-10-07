package tab.aid.sdk

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Coroutine-first convenience facade. All blocking OIDC work is dispatched to IO.
 */
class AidAsync internal constructor(private val client: AceID) {
    suspend fun login(context: Context): AidSession =
        withContext(Dispatchers.IO) {
            client.startAuthorization(context)
            throw AidLoginPendingException(
                "Authorization started. Route the callback URI to AceID.handleCallback() to complete login.",
            )
        }

    suspend fun restoreSession(context: Context): AidSessionState =
        withContext(Dispatchers.IO) {
            val session = client.getSession(context)
            when {
                session == null -> AidSessionState.Unauthenticated
                client.isAuthenticated(context) -> AidSessionState.Authenticated(session.user)
                session.tokens.refreshToken != null -> runCatching {
                    val token = client.getValidAccessToken(context)
                    if (token == null) AidSessionState.Unauthenticated
                    else AidSessionState.Authenticated(client.getUser(context) ?: session.user)
                }.getOrElse { AidSessionState.Expired }
                else -> AidSessionState.Expired
            }
        }

    suspend fun getAccount(context: Context, cache: Boolean = true): AidUser? =
        withContext(Dispatchers.IO) { client.getAccount(context, cache) }

    suspend fun getValidAccessToken(
        context: Context,
        leewaySeconds: Long = AceID.DEFAULT_TOKEN_LEEWAY_SECONDS,
    ): String? = client.validAccessTokenAsync(context, leewaySeconds)

    suspend fun logout(context: Context) =
        withContext(Dispatchers.IO) { client.signOut(context) }

    suspend fun validateConfiguration(): AidConfigurationReport =
        withContext(Dispatchers.IO) { client.validateConfiguration() }
}

sealed interface AidSessionState {
    data class Authenticated(val account: AidUser) : AidSessionState
    data object Unauthenticated : AidSessionState
    data object Expired : AidSessionState
}

class AidLoginPendingException(message: String) : AidException(message)

class AidConfigurationReport(
    val checks: List<AidConfigurationCheck>,
) {
    val isValid: Boolean get() = checks.all { it.ok }
}

data class AidConfigurationCheck(
    val name: String,
    val ok: Boolean,
    val detail: String,
)

internal class AidRefreshCoordinator {
    private val mutexes = ConcurrentHashMap<String, Mutex>()

    suspend fun <T> singleFlight(key: String, block: suspend () -> T): T =
        mutexes.computeIfAbsent(key) { Mutex() }.withLock { block() }
}
