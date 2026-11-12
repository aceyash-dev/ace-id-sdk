package tab.aid.sdk

import android.os.Handler
import android.os.Looper
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
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
 * It is built on `androidx.biometric`, which is the only supported way to reach
 * `BiometricPrompt`: the platform class has a package-private constructor and its
 * `PromptInfo` builder is not part of the public surface on every API level.
 */
data class AidBiometricOptions(
    val title: String = "Unlock Ace ID",
    val subtitle: String? = null,
    val description: String? = null,
    val negativeButtonText: String = "Use password",
    /** Accept device-credential fallback when the provider allows it. */
    val allowDeviceCredential: Boolean = false,
)

sealed interface AidBiometricResult {
    /** The user authenticated successfully. */
    data object Succeeded : AidBiometricResult

    /** The user dismissed the prompt or pressed the negative button. */
    data object Cancelled : AidBiometricResult

    /** The device or OS cannot show a biometric prompt. */
    data object Unavailable : AidBiometricResult

    /** The prompt reported an error, for example too many attempts. */
    data class Failed(val code: Int, val message: String?) : AidBiometricResult

    val isSuccess: Boolean get() = this is Succeeded
}

object AidBiometricUnlock {
    /**
     * Whether the device can show a biometric prompt.
     *
     * Checks enrolment rather than only hardware presence: a phone with a
     * fingerprint sensor but no enrolled finger cannot authenticate anyone.
     */
    @JvmStatic
    fun isSupported(activity: FragmentActivity): Boolean =
        canAuthenticate(activity, allowDeviceCredential = false)

    /** As [isSupported], optionally accepting the device credential as a fallback. */
    @JvmStatic
    fun canAuthenticate(activity: FragmentActivity, allowDeviceCredential: Boolean): Boolean {
        val authenticators = if (allowDeviceCredential) {
            BiometricManager.Authenticators.BIOMETRIC_WEAK or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_WEAK
        }
        return BiometricManager.from(activity).canAuthenticate(authenticators) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Show the biometric prompt and suspend until the user succeeds, cancels or
     * the prompt errors. Cancelling the coroutine dismisses the prompt.
     */
    @JvmStatic
    suspend fun unlock(
        activity: FragmentActivity,
        options: AidBiometricOptions = AidBiometricOptions(),
    ): AidBiometricResult {
        if (!canAuthenticate(activity, options.allowDeviceCredential)) {
            return AidBiometricResult.Unavailable
        }
        return prompt(activity, options)
    }

    private suspend fun prompt(
        activity: FragmentActivity,
        options: AidBiometricOptions,
    ): AidBiometricResult = suspendCancellableCoroutine { continuation ->
        val executor = Executor { runnable -> Handler(Looper.getMainLooper()).post(runnable) }

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                if (continuation.isActive) continuation.resume(AidBiometricResult.Succeeded)
            }

            override fun onAuthenticationFailed() {
                // A single non-matching finger is not terminal: the prompt stays
                // up and the user can try again, so nothing is resumed here.
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (!continuation.isActive) return
                val cancelled = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                    errorCode == BiometricPrompt.ERROR_CANCELED ||
                    errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                continuation.resume(
                    if (cancelled) AidBiometricResult.Cancelled
                    else AidBiometricResult.Failed(errorCode, errString.toString()),
                )
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)

        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle(options.title)
            .setAllowedAuthenticators(
                if (options.allowDeviceCredential) {
                    BiometricManager.Authenticators.BIOMETRIC_WEAK or
                        BiometricManager.Authenticators.DEVICE_CREDENTIAL
                } else {
                    BiometricManager.Authenticators.BIOMETRIC_WEAK
                },
            )
        options.subtitle?.let { builder.setSubtitle(it) }
        options.description?.let { builder.setDescription(it) }
        // A negative button is only allowed when the device credential is not
        // one of the accepted authenticators.
        if (!options.allowDeviceCredential) {
            builder.setNegativeButtonText(options.negativeButtonText)
        }

        continuation.invokeOnCancellation { prompt.cancelAuthentication() }

        try {
            prompt.authenticate(builder.build())
        } catch (error: Exception) {
            if (continuation.isActive) {
                continuation.resume(AidBiometricResult.Failed(-1, error.message))
            }
        }
    }
}
