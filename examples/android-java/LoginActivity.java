package com.example.app;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import tab.aid.sdk.AceID;
import tab.aid.sdk.AidException;
import tab.aid.sdk.AidNetworkPolicy;
import tab.aid.sdk.AidSession;
import tab.aid.sdk.AidSessionCallback;
import tab.aid.sdk.AidSessionState;
import tab.aid.sdk.AidUser;

/**
 * Java integration.
 *
 * The SDK's facade is Java-friendly: {@code @JvmOverloads} constructors, immutable
 * models with getters and {@code @JvmStatic} helpers. Suspend functions are
 * Kotlin-only, so Java uses the synchronous methods or the callback API.
 */
public class LoginActivity extends AppCompatActivity {

    private final AceID aceID = new AceID(
            "https://id.ace-base.cc",
            "your-public-client-id",
            "com.example.app:/oauth/callback",
            "openid profile email",
            6L * 60L * 60L * 1000L,
            30_000L,
            60L,
            AidNetworkPolicy.standard()
    );

    private final TextView status = new TextView(this);

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);

        Button signIn = new Button(this);
        signIn.setText("Sign in");
        signIn.setOnClickListener(view -> aceID.login(this, new AidSessionCallback() {
            @Override
            public void onSuccess(AidSession session) {
                render(session.getUser());
            }

            @Override
            public void onError(Throwable error) {
                Log.w("AceID", "Sign-in failed", error);
                status.setText("Sign-in failed");
            }
        }));

        Button signOut = new Button(this);
        signOut.setText("Sign out");
        signOut.setOnClickListener(view -> {
            aceID.logout(this);
            render(null);
        });

        layout.addView(signIn);
        layout.addView(signOut);
        layout.addView(status);
        setContentView(layout);

        render(aceID.getUser(this));

        // validateConfiguration() is a suspend function, so it is Kotlin-only.
        // Call it from a coroutine in development builds:
        //
        //   val report = aceID.validateConfiguration()
        //   if (!report.isValid) Log.w("AceID", report.checks.toString())
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        Uri data = intent.getData();
        if (data == null) return;
        try {
            AidSession session = aceID.handleCallback(this, data);
            render(session.getUser());
        } catch (AidException error) {
            Log.w("AceID", "Callback failed", error);
        }
    }

    private void render(@Nullable AidUser user) {
        if (user == null) {
            status.setText("Signed out");
            return;
        }
        String label = user.getEmail() != null ? user.getEmail() : user.getSubject();
        status.setText("Signed in as " + label);
        AidSessionState state = aceID.getSessionState().getValue();
        Log.i("AceID", "State: " + state);
    }
}
