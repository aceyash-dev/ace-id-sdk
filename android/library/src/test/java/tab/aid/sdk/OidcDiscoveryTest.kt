package tab.aid.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class OidcDiscoveryTest {
    @Test
    fun normalizeIssuerStripsTrailingSlashAndQuery() {
        assertEquals(
            "https://issuer.example.com/tenant",
            OidcDiscovery.normalizeIssuer("https://issuer.example.com/tenant///?ignored=true"),
        )
    }

    @Test
    fun httpIsRejectedExceptLocalhost() {
        assertThrows(AidDiscoveryException::class.java) {
            OidcDiscovery.normalizeIssuer("http://issuer.example.com")
        }
    }
}
