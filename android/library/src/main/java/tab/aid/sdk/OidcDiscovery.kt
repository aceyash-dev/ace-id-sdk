package tab.aid.sdk

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI

internal object OidcDiscovery {
    fun normalizeIssuer(issuer: String): String {
        if (issuer.isBlank()) throw AidDiscoveryException("Issuer must be a non-empty string")
        val uri = try { URI(issuer) } catch (e: Exception) {
            throw AidDiscoveryException("Issuer is not a valid URL", e)
        }
        if (!uri.isAbsolute || uri.isOpaque || uri.host.isNullOrBlank()) {
            throw AidDiscoveryException("Issuer must be an absolute hierarchical URL")
        }
        if (uri.rawUserInfo != null) {
            throw AidDiscoveryException("Issuer URL must not contain credentials")
        }
        if (uri.rawQuery != null || uri.rawFragment != null) {
            throw AidDiscoveryException("Issuer URL must not contain a query or fragment")
        }
        val scheme = uri.scheme.lowercase()
        val host = uri.host.trim('[', ']').lowercase()
        val isLocalhost = isLoopbackHost(host)
        if (scheme != "https" && !(isLocalhost && scheme == "http")) {
            throw AidDiscoveryException("Issuer must use HTTPS (HTTP loopback is allowed only for development)")
        }
        val path = uri.path.orEmpty().trimEnd('/')
        return URI(scheme, null, host, uri.port, if (path.isEmpty()) null else path, null, null)
            .toASCIIString().trimEnd('/')
    }

    fun fetch(issuer: String): OidcConfiguration {
        val normalized = normalizeIssuer(issuer)
        val endpoint = normalized + "/.well-known/openid-configuration"
        val connection = try {
            URI(endpoint).toURL().openConnection() as HttpURLConnection
        } catch (e: Exception) {
            throw AidDiscoveryException("Failed to open OIDC discovery URL", e)
        }
        try {
            connection.requestMethod = "GET"
            connection.setRequestProperty("Accept", "application/json")
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.instanceFollowRedirects = false
            if (connection.responseCode !in 200..299) {
                throw AidDiscoveryException("OIDC discovery request failed: HTTP " + connection.responseCode)
            }
            val json = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            return parse(json, normalized)
        } catch (e: AidDiscoveryException) {
            throw e
        } catch (e: Exception) {
            throw AidDiscoveryException("Failed to fetch OIDC discovery document", e)
        } finally {
            connection.disconnect()
        }
    }

    internal fun parse(json: String, normalizedIssuer: String): OidcConfiguration {
        val doc = try { JSONObject(json) } catch (e: Exception) {
            throw AidDiscoveryException("OIDC discovery document is not valid JSON", e)
        }
        val discoveredIssuer = doc.optString("issuer")
        if (discoveredIssuer.isBlank()) {
            throw AidDiscoveryException("OIDC discovery document is missing \"issuer\"")
        }
        if (normalizeIssuer(discoveredIssuer) != normalizedIssuer) {
            throw AidDiscoveryException("OIDC issuer does not match the configured issuer")
        }
        val authorizationEndpoint = validateEndpoint(doc.optString("authorization_endpoint"), "authorization_endpoint", normalizedIssuer)
        val tokenEndpoint = validateEndpoint(doc.optString("token_endpoint"), "token_endpoint", normalizedIssuer)
        val userInfoEndpoint = optionalEndpoint(doc.optString("userinfo_endpoint"), "userinfo_endpoint", normalizedIssuer)
        val jwksUri = optionalEndpoint(doc.optString("jwks_uri"), "jwks_uri", normalizedIssuer)
        val endSessionEndpoint = optionalEndpoint(doc.optString("end_session_endpoint"), "end_session_endpoint", normalizedIssuer)
        val revocationEndpoint = optionalEndpoint(doc.optString("revocation_endpoint"), "revocation_endpoint", normalizedIssuer)
        return OidcConfiguration(
            issuer = discoveredIssuer,
            authorizationEndpoint = authorizationEndpoint,
            tokenEndpoint = tokenEndpoint,
            userInfoEndpoint = userInfoEndpoint,
            jwksUri = jwksUri,
            endSessionEndpoint = endSessionEndpoint,
            revocationEndpoint = revocationEndpoint,
            codeChallengeMethodsSupported = doc.optJSONArray("code_challenge_methods_supported").strings(),
            responseTypesSupported = doc.optJSONArray("response_types_supported").strings(),
            grantTypesSupported = doc.optJSONArray("grant_types_supported").strings(),
        )
    }

    private fun optionalEndpoint(value: String, name: String, issuer: String): String? =
        value.takeIf { it.isNotBlank() }?.let { validateEndpoint(it, name, issuer) }

    private fun validateEndpoint(value: String, name: String, issuer: String): String {
        if (value.isBlank()) throw AidDiscoveryException("OIDC discovery document is missing \"$name\"")
        val endpoint = try { URI(value) } catch (e: Exception) {
            throw AidDiscoveryException("OIDC discovery \"$name\" is not a valid URL", e)
        }
        if (!endpoint.isAbsolute || endpoint.isOpaque || endpoint.host.isNullOrBlank()) {
            throw AidDiscoveryException("OIDC discovery \"$name\" must be an absolute URL")
        }
        if (endpoint.rawUserInfo != null || endpoint.rawFragment != null) {
            throw AidDiscoveryException("OIDC discovery \"$name\" must not contain credentials or fragments")
        }
        val issuerUrl = URI(issuer)
        val allowsHttpLoopback = isLoopbackHost(issuerUrl.host?.trim('[', ']'))
        val endpointLoopback = isLoopbackHost(endpoint.host?.trim('[', ']'))
        val endpointScheme = endpoint.scheme.lowercase()
        if (endpointScheme != "https" && !(allowsHttpLoopback && endpointLoopback && endpointScheme == "http")) {
            throw AidDiscoveryException("OIDC discovery \"$name\" must use HTTPS")
        }
        return endpoint.toASCIIString()
    }

    private fun isLoopbackHost(host: String?): Boolean =
        host?.lowercase() in setOf("localhost", "127.0.0.1", "::1")

    private fun org.json.JSONArray?.strings(): List<String> {
        if (this == null) return emptyList()
        return buildList(length()) { for (i in 0 until length()) add(optString(i)) }
    }
}
