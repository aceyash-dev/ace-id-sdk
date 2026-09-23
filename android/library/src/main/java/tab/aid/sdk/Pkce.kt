package tab.aid.sdk

import java.security.MessageDigest
import java.security.SecureRandom

internal object Pkce {
    private val secureRandom = SecureRandom()
    private const val BASE64_URL_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    fun randomString(byteLength: Int = 32): String {
        require(byteLength >= 16) { "byteLength must be >= 16" }
        val bytes = ByteArray(byteLength)
        secureRandom.nextBytes(bytes)
        return base64UrlEncode(bytes)
    }

    fun createCodeVerifier(byteLength: Int = 32): String {
        require(byteLength in 32..96) { "byteLength must be between 32 and 96 bytes" }
        return randomString(byteLength)
    }

    fun createCodeChallenge(verifier: String): String {
        require(verifier.length in 43..128) {
            "code_verifier must be between 43 and 128 characters"
        }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(verifier.toByteArray(Charsets.US_ASCII))
        return base64UrlEncode(digest)
    }

    private fun base64UrlEncode(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""

        val output = StringBuilder((bytes.size * 4 + 2) / 3)
        var index = 0

        while (index < bytes.size) {
            val remaining = bytes.size - index
            val first = bytes[index++].toInt() and 0xff
            val second = if (remaining > 1) bytes[index++].toInt() and 0xff else 0
            val third = if (remaining > 2) bytes[index++].toInt() and 0xff else 0

            output.append(BASE64_URL_ALPHABET[first ushr 2])
            output.append(BASE64_URL_ALPHABET[((first and 0x03) shl 4) or (second ushr 4)])

            if (remaining > 1) {
                output.append(BASE64_URL_ALPHABET[((second and 0x0f) shl 2) or (third ushr 6)])
            }
            if (remaining > 2) {
                output.append(BASE64_URL_ALPHABET[third and 0x3f])
            }
        }

        return output.toString()
    }
}
