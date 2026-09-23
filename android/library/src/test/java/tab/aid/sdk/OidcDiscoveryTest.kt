package tab.aid.sdk

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

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
        assertFailsWith<AidDiscoveryException> {
            OidcDiscovery.normalizeIssuer("http://issuer.example.com")
        }
    }
}
