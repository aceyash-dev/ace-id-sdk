package tab.aid.sdk

import java.net.HttpURLConnection
import java.net.URI

/** A minimal HTTP response: status plus body text. */
internal class AidHttpResponse(
    val status: Int,
    val body: String,
) {
    val isSuccessful: Boolean get() = status in 200..299
}

/**
 * The single place the SDK talks HTTP.
 *
 * Centralising the connection setup means timeouts, redirect policy and retry
 * classification cannot drift between discovery, token and UserInfo calls.
 *
 * `retryable` is decided by the caller, not inferred from the verb: discovery,
 * JWKS and UserInfo GETs may be repeated, while a token request must not be.
 */
internal object AidHttp {
    private const val MAX_BODY_BYTES = 512 * 1024

    fun get(
        endpoint: String,
        headers: Map<String, String>,
        policy: AidNetworkPolicy,
        retryable: Boolean,
    ): AidHttpResponse = execute(
        endpoint = endpoint,
        method = "GET",
        body = null,
        headers = headers,
        policy = policy,
        retryable = retryable,
    )

    fun postForm(
        endpoint: String,
        body: String,
        headers: Map<String, String>,
        policy: AidNetworkPolicy,
        retryable: Boolean,
    ): AidHttpResponse = execute(
        endpoint = endpoint,
        method = "POST",
        body = body,
        headers = headers,
        policy = policy,
        retryable = retryable,
    )

    private fun execute(
        endpoint: String,
        method: String,
        body: String?,
        headers: Map<String, String>,
        policy: AidNetworkPolicy,
        retryable: Boolean,
    ): AidHttpResponse {
        val attempts = if (retryable) policy.maxRetries else 0
        var lastError: Exception? = null

        for (attempt in 0..attempts) {
            val connection = try {
                URI(endpoint).toURL().openConnection() as HttpURLConnection
            } catch (e: Exception) {
                throw AidException("Failed to open $endpoint", e)
            }

            try {
                connection.requestMethod = method
                connection.connectTimeout = policy.connectTimeoutMs
                connection.readTimeout = policy.readTimeoutMs
                // Redirects are not followed: discovery and token endpoints are
                // pinned by the issuer, and a redirect could leave that origin.
                connection.instanceFollowRedirects = false
                for ((name, value) in headers) connection.setRequestProperty(name, value)
                if (body != null) {
                    connection.doOutput = true
                    connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                }

                val status = connection.responseCode
                val stream = if (status in 200..299) connection.inputStream else connection.errorStream
                val text = stream?.bufferedReader(Charsets.UTF_8)?.use { reader ->
                    val buffer = CharArray(8 * 1024)
                    val builder = StringBuilder()
                    while (true) {
                        val read = reader.read(buffer)
                        if (read < 0) break
                        builder.append(buffer, 0, read)
                        if (builder.length > MAX_BODY_BYTES) {
                            throw AidException("HTTP response exceeded the $MAX_BODY_BYTES-byte limit")
                        }
                    }
                    builder.toString()
                }.orEmpty()

                if (retryable && policy.isRetryableStatus(status) && attempt < attempts) {
                    val hinted = policy.retryAfterMs(connection.getHeaderField("Retry-After"))
                    sleep(hinted ?: policy.backoffDelayMs(attempt))
                    continue
                }
                return AidHttpResponse(status, text)
            } catch (e: AidException) {
                throw e
            } catch (e: Exception) {
                lastError = e
                if (attempt >= attempts) break
                sleep(policy.backoffDelayMs(attempt))
            } finally {
                connection.disconnect()
            }
        }

        throw AidException("HTTP request to $endpoint failed", lastError)
    }

    private fun sleep(millis: Long) {
        if (millis <= 0L) return
        try {
            Thread.sleep(millis)
        } catch (interrupted: InterruptedException) {
            // Preserve cancellation: a caller that interrupts wants out, not a retry.
            Thread.currentThread().interrupt()
            throw AidException("HTTP request was cancelled", interrupted)
        }
    }
}
