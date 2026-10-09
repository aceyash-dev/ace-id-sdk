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
