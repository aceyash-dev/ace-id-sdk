package tab.aid.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class OidcDiscoveryTest {
    @Test
    fun normalizeIssuerRemovesTrailingSlash() {
        assertEquals("https://issuer.example.com/tenant", OidcDiscovery.normalizeIssuer("https://issuer.example.com/tenant///"))
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
    fun discoveryRejectsInsecureAndCredentialedEndpoints() {
        val issuer = "https://issuer.example.com"
        val prefix = "\"issuer\":\"$issuer\",\"authorization_endpoint\":\"$issuer/authorize\",\"token_endpoint\":"
        val invalidEndpoints = listOf(
            "\"http://issuer.example.com/token\"",
            "\"https://user@issuer.example.com/token\"",
            "\"https://issuer.example.com/token#fragment\"",
        )
        invalidEndpoints.forEach { tokenEndpoint ->
            val json = "{$prefix$tokenEndpoint}"
            assertThrows(AidDiscoveryException::class.java) { OidcDiscovery.parse(json, issuer) }
        }
    }
}
