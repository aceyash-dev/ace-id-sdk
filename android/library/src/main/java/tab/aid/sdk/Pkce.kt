package tab.aid.sdk

import java.security.MessageDigest
import java.security.SecureRandom

internal object Pkce {
    private val secureRandom = SecureRandom()

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
        val table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        val out = StringBuilder((bytes.size * 4 + 2) / 3)
        var i = 0
        while (i + 2 < bytes.size) {
            val value = ((bytes[i].toInt() and 0xff) shl 16) or
                ((bytes[i + 1].toInt() and 0xff) shl 8) or
                (bytes[i + 2].toInt() and 0xff)
            out.append(table[value ushr 18 and 0x3f])
            out.append(table[value ushr 12 and 0x3f])
            out.append(table[value ushr 6 and 0x3f])
            out.append(table[value and 0x3f])
            i += 3
        }
        val remaining = bytes.size - i
        if (remaining == 1) {
            val value = bytes[i].toInt() and 0xff
            out.append(table[value ushr 2])
            out.append(table[value and 0x03 shl 4])
        } else if (remaining == 2) {
            val value = ((bytes[i].toInt() and 0xff) shl 8) or (bytes[i + 1].toInt() and 0xff)
            out.append(table[value ushr 10])
            out.append(table[value ushr 4 and 0x3f])
            out.append(table[value and 0x0f shl 2])
        }
        return out.toString().replace('+', '-').replace('/', '_')
    }
}
