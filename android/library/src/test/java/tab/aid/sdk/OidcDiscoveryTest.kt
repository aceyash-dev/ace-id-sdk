package tab.aid.sdk

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class OidcDiscoveryTest {
    @Test
    fun normalizeIssuerRemovesTrailingSlash() {
        assertEquals("https://issuer.example.com/tenant", OidcDiscovery.normalizeIssuer("https://issuer.example.com/tenant///"))
    }

    @Test
    fun normalizesCaseAndSupportsIPv6Loopback() {
        assertEquals("https://issuer.example.com", OidcDiscovery.normalizeIssuer("HTTPS://ISSUER.EXAMPLE.COM/"))
        assertEquals("http://[::1]:8080", OidcDiscovery.normalizeIssuer("http://[::1]:8080/"))
    }

    @Test
    fun issuerRejectsQueriesFragmentsAndCredentials() {
        listOf(
            "https://user@issuer.example.com",
            "https://issuer.example.com?tenant=ignored",
            "https://issuer.example.com/#fragment",
            "ftp://localhost",
        ).forEach { issuer ->
            assertThrows(AidDiscoveryException::class.java) { OidcDiscovery.normalizeIssuer(issuer) }
        }
    }

    @Test
    fun httpIsRejectedExceptLoopback() {
        assertThrows(AidDiscoveryException::class.java) {
            OidcDiscovery.normalizeIssuer("http://issuer.example.com")
        }
        assertEquals("http://localhost:8080", OidcDiscovery.normalizeIssuer("http://localhost:8080/"))
    }

    @Test
    fun acceptsCaseInsensitiveHttpsEndpointSchemes() {
        val issuer = "https://issuer.example.com"
        val json = JSONObject()
            .put("issuer", issuer)
            .put("authorization_endpoint", "HTTPS://issuer.example.com/authorize")
            .put("token_endpoint", "HTTPS://issuer.example.com/token")
            .toString()
        val configuration = OidcDiscovery.parse(json, issuer)
        assertEquals("HTTPS://issuer.example.com/authorize", configuration.authorizationEndpoint)
    }

    @Test
    fun discoveryRejectsInsecureAndCredentialedEndpoints() {
        val issuer = "https://issuer.example.com"
        val invalidEndpoints = listOf(
            "http://issuer.example.com/token",
            "https://user@issuer.example.com/token",
            "https://issuer.example.com/token#fragment",
        )
        invalidEndpoints.forEach { endpoint ->
            val json = JSONObject()
                .put("issuer", issuer)
                .put("authorization_endpoint", "$issuer/authorize")
                .put("token_endpoint", endpoint)
                .toString()
            assertThrows(AidDiscoveryException::class.java) {
                OidcDiscovery.parse(json, issuer)
            }
        }
    }
}
