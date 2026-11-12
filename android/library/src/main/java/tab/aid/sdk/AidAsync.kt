package tab.aid.sdk

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Coroutine-first convenience facade. All blocking OIDC work is dispatched to IO.
 */
class AidAsync internal constructor(private val client: AceID) {
    suspend fun login(context: Context): AidSession = client.login(context)

    suspend fun restoreSession(context: Context): AidSessionState =
        client.restoreSession(context)

    suspend fun getAccount(context: Context, cache: Boolean = true): AidUser? =
        client.getAccount(context, cache)

    /** Cross-platform alias of [getAccount]. */
    suspend fun getProfile(context: Context, cache: Boolean = true): AidUser? =
        client.getProfile(context, cache)

    suspend fun currentSession(context: Context): AidSession? =
        withContext(Dispatchers.IO) { client.currentSession(context) }

    suspend fun refreshSession(context: Context): AidSession = client.refreshSession(context)

    /** Whether an authorization transaction is waiting for its callback. */
    fun hasPendingAuthorization(context: Context): Boolean =
        client.hasPendingAuthorization(context)

    suspend fun getValidAccessToken(
        context: Context,
        leewaySeconds: Long = AceID.DEFAULT_TOKEN_LEEWAY_SECONDS,
    ): String? = client.getValidAccessTokenAsync(context, leewaySeconds)

    suspend fun logout(context: Context) =
        withContext(Dispatchers.IO) { client.signOut(context) }

    suspend fun validateConfiguration(): AidConfigurationReport =
        client.validateConfiguration()
}
