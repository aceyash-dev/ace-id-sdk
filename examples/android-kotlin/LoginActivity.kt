package com.example.app

import android.content.Intent
import android.os.Bundle
import android.util.Log
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import tab.aid.sdk.AceID
import tab.aid.sdk.AidBiometricUnlock
import tab.aid.sdk.AidSessionState

/**
 * Kotlin integration.
 *
 * The Activity must declare the redirect intent filter, for example:
 *
 *   <intent-filter android:autoVerify="false">
 *       <action android:name="android.intent.action.VIEW" />
 *       <category android:name="android.intent.category.DEFAULT" />
 *       <category android:name="android.intent.category.BROWSABLE" />
 *       <data android:scheme="com.example.app" android:path="/oauth/callback" />
 *   </intent-filter>
 */
class LoginActivity : FragmentActivity() {

    private val aceID = AceID(
        issuer = "https://id.ace-base.cc",
        clientId = "your-public-client-id",
        redirectUri = "com.example.app:/oauth/callback",
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // A process restart can land us here before the callback arrives. The
        // transaction is persisted, so we resume instead of starting a new flow.
        if (!aceID.hasPendingAuthorization(this)) {
            // Nothing to resume; the UI will offer a sign-in button.
        }

        setContent {
            val scope = rememberCoroutineScope()
            val state by aceID.authState.collectAsState()

            when (val current = state) {
                is AidSessionState.Authenticated -> {
                    Text("Signed in as ${current.account.email ?: current.account.subject}")
                    Button(onClick = { aceID.logout(applicationContext) }) { Text("Sign out") }
                }

                AidSessionState.Unauthenticated -> {
                    Button(onClick = {
                        scope.launch {
                            runCatching { aceID.login(this@LoginActivity) }
                                .onFailure { error -> Log.w("AceID", "Sign-in failed", error) }
                        }
                    }) { Text("Sign in") }
                }

                AidSessionState.Expired -> {
                    Button(onClick = {
                        scope.launch {
                            runCatching { aceID.refreshSession(applicationContext) }
                        }
                    }) { Text("Session expired — refresh") }
                }

                is AidSessionState.RefreshFailed -> {
                    Text("Could not refresh the session")
                    Button(onClick = { aceID.logout(applicationContext) }) { Text("Sign in again") }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.data?.let { uri ->
            lifecycleScope.launch {
                runCatching { aceID.handleCallbackAsync(applicationContext, uri) }
                    .onFailure { error -> Log.w("AceID", "Callback failed", error) }
            }
        }
    }

    /** Optional: gate the dashboard behind the device biometric prompt. */
    private fun unlockIfSupported() {
        if (!AidBiometricUnlock.isSupported(this)) return
        lifecycleScope.launch {
            val session = aceID.unlockSession(this@LoginActivity)
            Log.i("AceID", if (session != null) "Session unlocked" else "Unlock cancelled")
        }
    }
}
