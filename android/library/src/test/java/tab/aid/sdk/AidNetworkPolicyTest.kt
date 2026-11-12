package tab.aid.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AidNetworkPolicyTest {

    @Test
    fun defaultPolicyIsSane() {
        val policy = AidNetworkPolicy.standard()
        assertEquals(10_000L, policy.connectTimeoutMs.toLong())
        assertEquals(10_000L, policy.readTimeoutMs.toLong())
        assertEquals(2L, policy.maxRetries.toLong())
        assertTrue(policy.maxDelayMs >= policy.baseDelayMs)
    }

    @Test
    fun onlyTransientStatusesAreRetryable() {
        val policy = AidNetworkPolicy.standard()
        listOf(408, 425, 429, 500, 502, 503, 504).forEach {
            assertTrue("status $it should be retryable", policy.isRetryableStatus(it))
        }
        listOf(400, 401, 403, 404, 501, 505).forEach {
            assertFalse("status $it should not be retryable", policy.isRetryableStatus(it))
        }
    }

    @Test
    fun backoffGrowsThenCaps() {
        val policy = AidNetworkPolicy(baseDelayMs = 100, maxDelayMs = 400)
        // Jitter spreads each delay by up to a quarter, so assert the window.
        val first = policy.backoffDelayMs(0)
        assertTrue("first delay should be about 100ms, was $first", first in 50L..150L)
        val second = policy.backoffDelayMs(1)
        assertTrue("second delay should be about 200ms, was $second", second in 100L..300L)
        // Capped: every later attempt stays inside the ceiling.
        for (attempt in 2..10) {
            assertTrue(policy.backoffDelayMs(attempt) <= 400L)
            assertTrue(policy.backoffDelayMs(attempt) > 0L)
        }
        assertEquals(0L, policy.backoffDelayMs(-1))
    }

    @Test
    fun retryAfterIsParsedAndCapped() {
        val policy = AidNetworkPolicy(maxDelayMs = 2_000)
        assertEquals(2_000L, policy.retryAfterMs("3") ?: -1L)

        // A generous ceiling returns the provider's value unchanged.
        val generous = AidNetworkPolicy(maxDelayMs = 10_000)
        assertEquals(3_000L, generous.retryAfterMs("3") ?: -1L)
        assertEquals(2_000L, policy.retryAfterMs("120") ?: -1L)
        assertNull(policy.retryAfterMs(null))
        assertNull(policy.retryAfterMs(""))
        assertNull(policy.retryAfterMs("soon"))
        assertNull(policy.retryAfterMs("-5"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsNonPositiveConnectTimeout() {
        AidNetworkPolicy(connectTimeoutMs = 0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsExcessiveRetries() {
        AidNetworkPolicy(maxRetries = 9)
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsInvertedBackoff() {
        AidNetworkPolicy(baseDelayMs = 1_000, maxDelayMs = 10)
    }

    @Test
    fun noRetriesKeepsTimeouts() {
        val policy = AidNetworkPolicy.noRetries()
        assertEquals(0L, policy.maxRetries.toLong())
        assertEquals(10_000L, policy.readTimeoutMs.toLong())
    }
}
