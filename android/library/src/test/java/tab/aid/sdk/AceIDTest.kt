package tab.aid.sdk

import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue

class AceIDTest {

    @Test
    fun transactionTimestampValidationRejectsExpiredAndFutureTransactions() {
        val now = 1_000_000L
        fun transaction(createdAt: Long) = AidTransaction(
            state = "state",
            nonce = "nonce",
            codeVerifier = "verifier",
            redirectUri = "com.example.app:/callback",
            createdAt = createdAt,
        )
        assertTrue(transaction(now).hasValidTimestamp(nowMillis = now))
        assertTrue(transaction(now - AceID.DEFAULT_TRANSACTION_TTL_MS).hasValidTimestamp(nowMillis = now))
        assertFalse(transaction(0L).hasValidTimestamp(nowMillis = now))
        assertFalse(transaction(now + AceID.MAX_TRANSACTION_FUTURE_SKEW_MS + 1).hasValidTimestamp(nowMillis = now))
        assertFalse(transaction(now - AceID.DEFAULT_TRANSACTION_TTL_MS - 1).hasValidTimestamp(nowMillis = now))
    }

    @Test
    fun authorizationOptionsSupportStepUpHints() {
        val options = AidAuthorizationOptions(
            prompt = "login consent", loginHint = "alice@example.test", maxAgeSeconds = 0,
            acrValues = listOf("urn:ace:loa:2"), uiLocales = listOf("en-US", "fr-FR"),
            additionalParameters = mapOf("organization" to "acme"),
        )
        assertEquals("login consent", options.prompt)
        assertEquals(0L, options.maxAgeSeconds)
        assertEquals(listOf("urn:ace:loa:2"), options.acrValues)
        assertEquals("acme", options.additionalParameters["organization"])
    }

    @Test(expected = AidConfigurationException::class)
    fun authorizationOptionsRejectSecurityParameterOverrides() {
        AidAuthorizationOptions(additionalParameters = mapOf("STATE" to "attacker-controlled"))
    }

    @Test(expected = AidConfigurationException::class)
    fun authorizationOptionsRejectNegativeMaxAge() {
        AidAuthorizationOptions(maxAgeSeconds = -1)
    }

    @Test
    fun idTokenValidationRequiresIssuedAtAndChecksAuthorizedParty() {
        val now = 1_000_000L
        AidJwtVerifier.validateIssuedAtAndAuthorizedParty(
            org.json.JSONObject("""{"iat":999990,"aud":"client"}"""), "client", now,
        )
        assertTrue(runCatching {
            AidJwtVerifier.validateIssuedAtAndAuthorizedParty(
                org.json.JSONObject("""{"aud":"client"}"""), "client", now,
            )
        }.exceptionOrNull() is AidException)
        assertTrue(runCatching {
            AidJwtVerifier.validateIssuedAtAndAuthorizedParty(
                org.json.JSONObject("""{"iat":1001000,"aud":"client"}"""), "client", now,
            )
        }.exceptionOrNull() is AidException)
        assertTrue(runCatching {
            AidJwtVerifier.validateIssuedAtAndAuthorizedParty(
                org.json.JSONObject("""{"iat":999990,"aud":"client","azp":"other"}"""), "client", now,
            )
        }.exceptionOrNull() is AidException)
        assertTrue(runCatching {
            AidJwtVerifier.validateIssuedAtAndAuthorizedParty(
                org.json.JSONObject("""{"iat":999990,"aud":["client","other"]}"""), "client", now,
            )
        }.exceptionOrNull() is AidException)
        AidJwtVerifier.validateAuthenticationTime(
            org.json.JSONObject("""{"auth_time":999990}"""), 60L, now,
        )
        assertTrue(runCatching {
            AidJwtVerifier.validateAuthenticationTime(org.json.JSONObject("{}"), 60L, now)
        }.exceptionOrNull() is AidException)
        assertTrue(runCatching {
            AidJwtVerifier.validateAuthenticationTime(
                org.json.JSONObject("""{"auth_time":999000}"""), 30L, now,
            )
        }.exceptionOrNull() is AidException)
    }

    @Test
    fun idTokenTimeClaimsRequireNumericExpiryAndRejectExpiredOrFutureNotBefore() {
        val now = 1_000_000L
        AidJwtVerifier.validateTimeClaims(
            org.json.JSONObject("""{"exp":1000100,"nbf":999999}"""), now,
        )
        assertTrue(runCatching {
            AidJwtVerifier.validateTimeClaims(org.json.JSONObject("""{"exp":"1000100"}"""), now)
        }.exceptionOrNull() is AidException)
        assertTrue(runCatching {
            AidJwtVerifier.validateTimeClaims(org.json.JSONObject("""{"exp":999000}"""), now)
        }.exceptionOrNull() is AidException)
        assertTrue(runCatching {
            AidJwtVerifier.validateTimeClaims(
                org.json.JSONObject("""{"exp":1000100,"nbf":1000100}"""), now,
            )
        }.exceptionOrNull() is AidException)
        assertTrue(runCatching {
            AidJwtVerifier.validateTimeClaims(
                org.json.JSONObject("""{"exp":1000100,"nbf":"999999"}"""), now,
            )
        }.exceptionOrNull() is AidException)
    }

    @Test
    fun oversizedIdTokenIsRejectedBeforeParsing() {
        assertTrue(runCatching {
            AidJwtVerifier.validateTokenSize("a".repeat(AidJwtVerifier.MAX_ID_TOKEN_BYTES + 1))
        }.exceptionOrNull() is AidException)
        AidJwtVerifier.validateTokenSize("a".repeat(AidJwtVerifier.MAX_ID_TOKEN_BYTES))
    }

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
