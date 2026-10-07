package tab.aid.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AceIdModelTest {
    @Test
    fun normalizedUserFieldsComeFromClaims() {
        val user = AidUser(
            subject = "sub-123",
            claims = mapOf(
                "email" to "user@example.com",
                "name" to "Ace User",
                "picture" to "https://example.com/p.png",
                "preferred_username" to "ace-user",
                "custom" to "value",
            ),
        )

        assertEquals("sub-123", user.subject)
        assertEquals("user@example.com", user.email)
        assertEquals("Ace User", user.name)
        assertEquals("https://example.com/p.png", user.picture)
        assertEquals("ace-user", user.username)
        assertEquals("value", user.claims["custom"])
    }

    @Test
    fun usernameFallsBackToUsernameClaim() {
        val user = AidUser("sub", mapOf("username" to "legacy-user"))
        assertEquals("legacy-user", user.username)
    }

    @Test
    fun pkceVerifierAndChallengeAreValidS256() {
        val verifier = Pkce.createCodeVerifier()
        val challenge = Pkce.createCodeChallenge(verifier)

        assertTrue(verifier.length in 43..128)
        assertTrue(challenge.length in 43..128)
        assertEquals(challenge, Pkce.createCodeChallenge(verifier))
    }

    @Test
    fun insecureRedirectUriIsRejected() {
        var rejected = false
        try {
            AceID(
                issuer = "https://id.example.com",
                clientId = "client",
                redirectUri = "http://evil.example.com/callback",
            )
        } catch (_: AidConfigurationException) {
            rejected = true
        }
        assertTrue(rejected)
    }
}
