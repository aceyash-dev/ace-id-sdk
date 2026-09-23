package tab.aid.sdk

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PkceTest {
    @Test
    fun verifierIsRfc7636Sized() {
        val verifier = Pkce.createCodeVerifier()
        assertTrue(verifier.length in 43..128)
    }

    @Test
    fun challengeMatchesRfc7636Example() {
        val verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        assertEquals(
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            Pkce.createCodeChallenge(verifier),
        )
    }
}
