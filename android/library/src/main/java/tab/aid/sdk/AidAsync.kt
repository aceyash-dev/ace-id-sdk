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

    suspend fun getValidAccessToken(
        context: Context,
        leewaySeconds: Long = AceID.DEFAULT_TOKEN_LEEWAY_SECONDS,
    ): String? = client.getValidAccessTokenAsync(context, leewaySeconds)

    suspend fun logout(context: Context) =
        withContext(Dispatchers.IO) { client.signOut(context) }

    suspend fun validateConfiguration(): AidConfigurationReport =
        client.validateConfiguration()
}
