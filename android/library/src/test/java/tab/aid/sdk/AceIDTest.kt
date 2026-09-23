package tab.aid.sdk

import org.junit.Test
import org.junit.Assert.assertEquals

class AceIDTest {
    @Test
    fun configurationIsExposed() {
        val aid = AceID(
            issuer = "https://issuer.example.com",
            clientId = "client",
            redirectUri = "com.example.app:/oauth2redirect",
        )

        assertEquals("https://issuer.example.com", aid.issuer)
        assertEquals("client", aid.clientId)
        assertEquals("com.example.app:/oauth2redirect", aid.redirectUri)
    }
}
