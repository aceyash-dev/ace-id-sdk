package tab.aid.sdk

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI

internal object OidcDiscovery {
    fun normalizeIssuer(issuer: String): String {
        if (issuer.isBlank()) throw AidDiscoveryException("Issuer must be a non-empty string")
        val uri = try { URI(issuer) } catch (e: Exception) {
            throw AidDiscoveryException("Issuer is not a valid URL: " + issuer, e)
        }
        val isLocalhost = uri.host == "localhost" || uri.host == "127.0.0.1"
        if (uri.scheme != "https" && !isLocalhost) {
            throw AidDiscoveryException("Issuer must use HTTPS (localhost/127.0.0.1 exempt for development)")
        }
        val path = uri.path.orEmpty().trimEnd('/')
        return URI(uri.scheme, uri.userInfo, uri.host, uri.port, if (path.isEmpty()) null else path, null, null)
            .toString().trimEnd('/')
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
            if (connection.responseCode !in 200..299) {
                throw AidDiscoveryException("OIDC discovery request failed: HTTP " + connection.responseCode)
            }
            val json = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            return parse(json, normalized)
        } catch (e: AidDiscoveryException) {
            throw e
        } catch (e: Exception) {
            throw AidDiscoveryException("Failed to fetch OIDC discovery document from " + endpoint, e)
        } finally {
            connection.disconnect()
        }
    }

    private fun parse(json: String, normalizedIssuer: String): OidcConfiguration {
        val doc = try { JSONObject(json) } catch (e: Exception) {
            throw AidDiscoveryException("OIDC discovery document is not valid JSON", e)
        }
        val discoveredIssuer = doc.optString("issuer")
        if (discoveredIssuer.isBlank()) throw AidDiscoveryException("OIDC discovery document is missing "issuer"")
        if (normalizeIssuer(discoveredIssuer) != normalizedIssuer) {
            throw AidDiscoveryException("OIDC issuer mismatch: expected " + normalizedIssuer + ", received " + discoveredIssuer)
        }
        val authorizationEndpoint = doc.optString("authorization_endpoint")
        if (authorizationEndpoint.isBlank()) throw AidDiscoveryException("OIDC discovery document is missing "authorization_endpoint"")
        val tokenEndpoint = doc.optString("token_endpoint")
        if (tokenEndpoint.isBlank()) throw AidDiscoveryException("OIDC discovery document is missing "token_endpoint"")
        return OidcConfiguration(
            issuer = normalizedIssuer,
            authorizationEndpoint = authorizationEndpoint,
            tokenEndpoint = tokenEndpoint,
            userInfoEndpoint = doc.optString("userinfo_endpoint").takeIf { it.isNotBlank() },
            jwksUri = doc.optString("jwks_uri").takeIf { it.isNotBlank() },
            endSessionEndpoint = doc.optString("end_session_endpoint").takeIf { it.isNotBlank() },
            revocationEndpoint = doc.optString("revocation_endpoint").takeIf { it.isNotBlank() },
            codeChallengeMethodsSupported = doc.optJSONArray("code_challenge_methods_supported").strings(),
            responseTypesSupported = doc.optJSONArray("response_types_supported").strings(),
            grantTypesSupported = doc.optJSONArray("grant_types_supported").strings(),
        )
    }

    private fun org.json.JSONArray?.strings(): List<String> {
        if (this == null) return emptyList()
        return buildList(length()) { for (i in 0 until length()) add(optString(i)) }
    }
}
