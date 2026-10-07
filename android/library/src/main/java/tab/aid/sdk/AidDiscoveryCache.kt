package tab.aid.sdk

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap

internal class AidDiscoveryCache(
    private val context: Context,
    private val issuer: String,
    private val clientId: String,
    private val ttlMs: Long,
) {
    companion object {
        private const val KEY = "discovery"
        private const val MAX_CACHE_BYTES = 64 * 1024
        private val memory = ConcurrentHashMap<String, Entry>()
        private val locks = ConcurrentHashMap<String, Any>()
    }

    private data class Entry(val configuration: OidcConfiguration, val expiresAt: Long)

    private val normalizedIssuer = OidcDiscovery.normalizeIssuer(issuer)
    private val memoryKey = "$normalizedIssuer|$clientId"
    private val lock = locks.computeIfAbsent(memoryKey) { Any() }

    fun get(forceRefresh: Boolean = false): OidcConfiguration {
        val now = System.currentTimeMillis()
        if (!forceRefresh) {
            memory[memoryKey]?.takeIf { it.expiresAt > now }?.let { return it.configuration }
            readDisk()?.takeIf { it.expiresAt > now }?.let {
                memory[memoryKey] = it
                return it.configuration
            }
        }

        synchronized(lock) {
            val secondChance = memory[memoryKey]
            if (!forceRefresh && secondChance != null && secondChance.expiresAt > now) {
                return secondChance.configuration
            }
            val disk = if (!forceRefresh) readDisk() else null
            if (disk != null && disk.expiresAt > now) {
                memory[memoryKey] = disk
                return disk.configuration
            }

            val configuration = OidcDiscovery.fetch(normalizedIssuer)
            val entry = Entry(configuration, System.currentTimeMillis() + ttlMs.coerceAtLeast(1L))
            memory[memoryKey] = entry
            writeDisk(entry)
            return configuration
        }
    }

    fun clear() {
        memory.remove(memoryKey)
        AidSecureStorage(context, normalizedIssuer, clientId).remove(KEY)
    }

    private fun readDisk(): Entry? {
        val raw = runCatching {
            AidSecureStorage(context, normalizedIssuer, clientId).get(KEY)
        }.getOrNull() ?: return null
        return runCatching {
            val value = JSONObject(raw)
            val expiresAt = value.getLong("expires_at")
            Entry(parse(value.getJSONObject("configuration")), expiresAt)
        }.getOrNull()
    }

    private fun writeDisk(entry: Entry) {
        val configuration = entry.configuration
        val json = JSONObject()
            .put("expires_at", entry.expiresAt)
            .put(
                "configuration",
                JSONObject()
                    .put("issuer", configuration.issuer)
                    .put("authorization_endpoint", configuration.authorizationEndpoint)
                    .put("token_endpoint", configuration.tokenEndpoint)
                    .put("userinfo_endpoint", configuration.userInfoEndpoint)
                    .put("jwks_uri", configuration.jwksUri)
                    .put("end_session_endpoint", configuration.endSessionEndpoint)
                    .put("revocation_endpoint", configuration.revocationEndpoint)
                    .put("code_challenge_methods_supported", JSONArray(configuration.codeChallengeMethodsSupported))
                    .put("response_types_supported", JSONArray(configuration.responseTypesSupported))
                    .put("grant_types_supported", JSONArray(configuration.grantTypesSupported)),
            )
        if (json.toString().toByteArray(Charsets.UTF_8).size <= MAX_CACHE_BYTES) {
            AidSecureStorage(context, normalizedIssuer, clientId).put(KEY, json.toString())
        }
    }

    private fun parse(value: JSONObject): OidcConfiguration = OidcConfiguration(
        issuer = value.getString("issuer"),
        authorizationEndpoint = value.getString("authorization_endpoint"),
        tokenEndpoint = value.getString("token_endpoint"),
        userInfoEndpoint = value.optString("userinfo_endpoint").takeIf { it.isNotBlank() },
        jwksUri = value.optString("jwks_uri").takeIf { it.isNotBlank() },
        endSessionEndpoint = value.optString("end_session_endpoint").takeIf { it.isNotBlank() },
        revocationEndpoint = value.optString("revocation_endpoint").takeIf { it.isNotBlank() },
        codeChallengeMethodsSupported = value.optJSONArray("code_challenge_methods_supported").strings(),
        responseTypesSupported = value.optJSONArray("response_types_supported").strings(),
        grantTypesSupported = value.optJSONArray("grant_types_supported").strings(),
    )

    private fun JSONArray?.strings(): List<String> {
        if (this == null) return emptyList()
        return buildList(length()) { for (i in 0 until length()) add(optString(i)) }
    }
}
