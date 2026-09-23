package tab.aid.sdk

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

internal object Pkce {
    fun randomString(byteLength: Int = 32): String {
        require(byteLength >= 16) { "byteLength must be >= 16" }
        val bytes = ByteArray(byteLength)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
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
        return Base64.encodeToString(
            digest,
            Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
        )
    }
}
