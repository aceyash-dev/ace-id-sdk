package tab.aid.sdk

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal class AidSecureStorage(
    context: Context,
    issuer: String,
    clientId: String,
) {
    private val prefs = context.applicationContext.getSharedPreferences(
        "tab.aid.sdk.secure",
        Context.MODE_PRIVATE,
    )
    private val keyAlias = "tab.aid.sdk." + sha256("$issuer|$clientId").take(40)

    fun put(name: String, value: String) {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key())
            val ciphertext = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
            val payload = ByteBuffer.allocate(4 + cipher.iv.size + ciphertext.size)
                .putInt(cipher.iv.size)
                .put(cipher.iv)
                .put(ciphertext)
                .array()
            prefs.edit()
                .putString(scopedName(name), Base64.encodeToString(payload, Base64.NO_WRAP))
                .commit()
        } catch (e: Exception) {
            throw AidException("Failed to securely store SDK data", e)
        }
    }

    fun get(name: String): String? {
        val encoded = prefs.getString(scopedName(name), null) ?: return null
        return try {
            val payload = Base64.decode(encoded, Base64.NO_WRAP)
            val buffer = ByteBuffer.wrap(payload)
            val ivLength = buffer.int
            require(ivLength in 12..16 && ivLength <= buffer.remaining())
            val iv = ByteArray(ivLength)
            buffer.get(iv)
            val ciphertext = ByteArray(buffer.remaining())
            buffer.get(ciphertext)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        } catch (e: Exception) {
            throw AidException("Failed to securely read SDK data", e)
        }
    }

    fun remove(name: String) {
        prefs.edit().remove(scopedName(name)).commit()
    }

    private fun scopedName(name: String): String = "$name.$keyAlias"

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore")
        store.load(null)
        val existing = store.getKey(keyAlias, null)
        if (existing is SecretKey) return existing

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            "AndroidKeyStore",
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build(),
        )
        return generator.generateKey()
    }

    private fun sha256(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}
