package tab.aid.sdk

import java.util.concurrent.ConcurrentHashMap

internal object AidSdkRuntime {
    private const val DISCOVERY_TTL_MS = 10 * 60 * 1000L
    private const val ACCOUNT_TTL_MS = 30 * 1000L

    private data class DiscoveryEntry(
        val configuration: OidcConfiguration,
        val fetchedAt: Long,
    )

    private data class AccountEntry(
        val account: AidUser,
        val cachedAt: Long,
    )

    private val discoveryCache = ConcurrentHashMap<String, DiscoveryEntry>()
    private val accountCache = ConcurrentHashMap<String, AccountEntry>()
    private val refreshLocks = ConcurrentHashMap<String, Any>()

    fun discovery(issuer: String, loader: () -> OidcConfiguration): OidcConfiguration {
        val now = System.currentTimeMillis()
        discoveryCache[issuer]?.let { entry ->
            if (now - entry.fetchedAt <= DISCOVERY_TTL_MS) return entry.configuration
        }

        synchronized(lockFor("discovery:$issuer")) {
            val refreshedNow = System.currentTimeMillis()
            discoveryCache[issuer]?.let { entry ->
                if (refreshedNow - entry.fetchedAt <= DISCOVERY_TTL_MS) return entry.configuration
            }
            return loader().also {
                discoveryCache[issuer] = DiscoveryEntry(it, refreshedNow)
            }
        }
    }

    fun <T> withRefreshLock(key: String, action: () -> T): T =
        synchronized(lockFor("refresh:$key")) { action() }

    fun account(key: String): AidUser? {
        val entry = accountCache[key] ?: return null
        return if (System.currentTimeMillis() - entry.cachedAt <= ACCOUNT_TTL_MS) {
            entry.account
        } else {
            accountCache.remove(key)
            null
        }
    }

    fun putAccount(key: String, account: AidUser) {
        accountCache[key] = AccountEntry(account, System.currentTimeMillis())
    }

    fun clearAccount(key: String) {
        accountCache.remove(key)
    }

    fun clearIssuer(issuer: String, clientId: String) {
        discoveryCache.remove(issuer)
        clearAccount(cacheKey(issuer, clientId))
    }

    fun cacheKey(issuer: String, clientId: String): String = "$issuer|$clientId"

    private fun lockFor(key: String): Any =
        refreshLocks.computeIfAbsent(key) { Any() }
}
