package tab.aid.sdk

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.Executor
import kotlin.coroutines.resume

/**
 * Optional biometric gate for a locally stored session.
 *
 * This is a *local* convenience lock, not an authentication factor for the
 * identity provider: the OIDC session is still governed by its tokens, MFA and
 * provider policy. An application opts in when it wants "unlock the app with
 * your fingerprint" without asking the user to complete a full sign-in again.
 *
 * It uses the platform `BiometricPrompt` (API 28+) rather than a support library
 * so the SDK gains no new dependency and no extra manifest entries. On older
 * devices [isSupported] returns false and the caller should fall back to a normal
 * sign-in.
 */
data class AidBiometricOptions(
    val title: String = "Unlock Ace ID",
    val subtitle: String? = null,
    val description: String? = null,
    val negativeButtonText: String = "Use password",
)

sealed interface AidBiometricResult {
    /** The user authenticated successfully. */
    data object Succeeded : AidBiometricResult

    /** The user dismissed the prompt or cancelled. */
    data object Cancelled : AidBiometricResult

    /** The device or OS cannot show a biometric prompt. */
    data object Unavailable : AidBiometricResult

    /** The prompt reported an error, for example too many attempts. */
    data class Failed(val code: Int, val message: String?) : AidBiometricResult

    val isSuccess: Boolean get() = this is Succeeded
}

object AidBiometricUnlock {
    /** Minimum platform version that exposes [BiometricPrompt]. */
    const val MIN_SDK: Int = Build.VERSION_CODES.P

    /** Whether the device can show a biometric prompt at all. */
    @JvmStatic
    fun isSupported(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < MIN_SDK) return false
        val manager = context.packageManager
        return manager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT) ||
            manager.hasSystemFeature(FEATURE_BIOMETRIC_ANY)
    }

    /**
     * Show the biometric prompt and suspend until the user succeeds, cancels or
     * the prompt errors. Cancelling the coroutine dismisses the prompt.
     */
    @JvmStatic
    suspend fun unlock(
        activity: Activity,
        options: AidBiometricOptions = AidBiometricOptions(),
    ): AidBiometricResult {
        if (Build.VERSION.SDK_INT < MIN_SDK) return AidBiometricResult.Unavailable
        if (!isSupported(activity)) return AidBiometricResult.Unavailable
        return prompt(activity, options)
    }

    private suspend fun prompt(
        activity: Activity,
        options: AidBiometricOptions,
    ): AidBiometricResult = suspendCancellableCoroutine { continuation ->
        val signal = CancellationSignal()
        val executor = Executor { runnable -> Handler(Looper.getMainLooper()).post(runnable) }

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                if (continuation.isActive) continuation.resume(AidBiometricResult.Succeeded)
            }

            override fun onAuthenticationFailed() {
                // A single non-matching finger is not terminal: the prompt stays
                // up and the user can try again, so nothing is resumed here.
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                if (!continuation.isActive) return
                val cancelled = errorCode == BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.BIOMETRIC_ERROR_CANCELED
                continuation.resume(
                    if (cancelled) AidBiometricResult.Cancelled
                    else AidBiometricResult.Failed(errorCode, errString?.toString()),
                )
            }
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(options.title)
            .setNegativeButtonText(options.negativeButtonText)
            .apply {
                options.subtitle?.let { setSubtitle(it) }
                options.description?.let { setDescription(it) }
            }
            .build()

        continuation.invokeOnCancellation { signal.cancel() }

        try {
            BiometricPrompt(activity, executor, callback).authenticate(promptInfo, signal)
        } catch (error: Exception) {
            if (continuation.isActive) {
                continuation.resume(AidBiometricResult.Failed(-1, error.message))
            }
        }
    }

    /**
     * `PackageManager.FEATURE_BIOMETRIC_ANY` is only public from API 29, so the
     * literal is used to keep this file compiling against every compileSdk.
     */
    private const val FEATURE_BIOMETRIC_ANY = "android.hardware.biometrics.face"
}
