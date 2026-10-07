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
    fun authorizationRequestUsesPkceS256() {
        val ace = AceID(
            issuer = "https://id.example.com",
            clientId = "client",
            redirectUri = "com.example.app:/oauth/callback",
        )
        val request = ace.createAuthorizationRequest(
            OidcConfiguration(
                issuer = "https://id.example.com",
                authorizationEndpoint = "https://id.example.com/authorize",
                tokenEndpoint = "https://id.example.com/token",
                codeChallengeMethodsSupported = listOf("S256"),
            ),
        )

        assertTrue(request.url.contains("code_challenge_method=S256"))
        assertTrue(request.url.contains("response_type=code"))
        assertTrue(request.state.isNotBlank())
        assertTrue(request.nonce.isNotBlank())
        assertTrue(request.codeVerifier.isNotBlank())
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
