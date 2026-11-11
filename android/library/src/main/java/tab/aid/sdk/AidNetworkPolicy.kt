package tab.aid.sdk

/**
 * Timeouts and retry behaviour for the SDK's HTTP calls.
 *
 * Retries are limited to operations that are safe to repeat. A discovery
 * document, a JWKS key set and a UserInfo response are all idempotent GETs, so a
 * transient 503 or a dropped connection can be retried. An authorization-code
 * exchange is *not* safe to repeat: the code is single-use, and a second attempt
 * after a slow-but-successful first one fails with `invalid_grant`. A refresh
 * token exchange is excluded for the same reason — with rotation, a retry can
 * invalidate the session it was trying to extend.
 *
 * This type is deliberately free of Android dependencies so it can be unit
 * tested on the JVM.
 */
data class AidNetworkPolicy(
    /** TCP connect timeout per attempt. */
    val connectTimeoutMs: Int = DEFAULT_CONNECT_TIMEOUT_MS,
    /** Socket read timeout per attempt. */
    val readTimeoutMs: Int = DEFAULT_READ_TIMEOUT_MS,
    /** Additional attempts for retry-safe requests. `0` disables retries. */
    val maxRetries: Int = DEFAULT_MAX_RETRIES,
    /** First backoff delay. */
    val baseDelayMs: Long = DEFAULT_BASE_DELAY_MS,
    /** Backoff ceiling. */
    val maxDelayMs: Long = DEFAULT_MAX_DELAY_MS,
) {
    init {
        require(connectTimeoutMs > 0) { "connectTimeoutMs must be > 0" }
        require(readTimeoutMs > 0) { "readTimeoutMs must be > 0" }
        require(maxRetries in 0..MAX_ALLOWED_RETRIES) {
            "maxRetries must be between 0 and $MAX_ALLOWED_RETRIES"
        }
        require(baseDelayMs >= 0) { "baseDelayMs must not be negative" }
        require(maxDelayMs >= baseDelayMs) { "maxDelayMs must be >= baseDelayMs" }
    }

    /** Whether a response status is worth repeating. */
    fun isRetryableStatus(status: Int): Boolean = when (status) {
        408, 425, 429 -> true
        in 500..599 -> status != 501 && status != 505
        else -> false
    }

    /**
     * Exponential backoff for attempt `attempt` (0-based), capped at
     * [maxDelayMs]. A little jitter keeps a fleet of devices from retrying in
     * lockstep after a provider outage.
     */
    fun backoffDelayMs(attempt: Int): Long {
        if (attempt < 0) return 0L
        val exponent = attempt.coerceAtMost(MAX_BACKOFF_EXPONENT)
        val scaled = baseDelayMs shl exponent
        val capped = scaled.coerceAtMost(maxDelayMs)
        if (capped <= 0L) return 0L
        val jitter = (capped / 4).coerceAtLeast(0L)
        if (jitter == 0L) return capped
        // Spread retries across a quarter of the window so a fleet of devices
        // does not hammer the provider in lockstep after an outage.
        val noise = kotlin.math.abs(System.nanoTime() % (jitter + 1L))
        return (capped - jitter / 2 + noise).coerceIn(0L, maxDelayMs)
    }

    /** Parse a `Retry-After` header in seconds form, capped by [maxDelayMs]. */
    fun retryAfterMs(value: String?): Long? {
        if (value.isNullOrBlank()) return null
        val seconds = value.trim().toLongOrNull() ?: return null
        if (seconds < 0L) return null
        return (seconds * 1000L).coerceAtMost(maxDelayMs)
    }

    companion object {
        const val DEFAULT_CONNECT_TIMEOUT_MS = 10_000
        const val DEFAULT_READ_TIMEOUT_MS = 10_000
        const val DEFAULT_MAX_RETRIES = 2
        const val DEFAULT_BASE_DELAY_MS = 200L
        const val DEFAULT_MAX_DELAY_MS = 2_000L
        private const val MAX_ALLOWED_RETRIES = 5
        private const val MAX_BACKOFF_EXPONENT = 6

        /** The SDK default: 10s timeouts and two retries for safe requests. */
        @JvmStatic
        fun default(): AidNetworkPolicy = AidNetworkPolicy()

        /** No retries, for callers that need strict single-attempt behaviour. */
        @JvmStatic
        fun noRetries(): AidNetworkPolicy = AidNetworkPolicy(maxRetries = 0)
    }
}
