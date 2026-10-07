package tab.aid.sdk;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class AceIDJavaApiTest {
    @Test
    public void javaCanUsePublicFacade() {
        AceID client = new AceID(
            "https://identity.example.com",
            "client-id",
            "com.example.app:/oauth/callback"
        );

        OidcConfiguration configuration = new OidcConfiguration(
            "https://identity.example.com",
            "https://identity.example.com/authorize",
            "https://identity.example.com/token",
            null,
            "https://identity.example.com/jwks",
            null,
            null,
            java.util.Collections.singletonList("S256"),
            java.util.Collections.singletonList("code"),
            java.util.Collections.singletonList("authorization_code")
        );

        AuthorizationRequest request = new AuthorizationRequest(
            "https://identity.example.com/authorize?response_type=code",
            "state",
            "nonce",
            "code-verifier",
            "com.example.app:/oauth/callback"
        );

        assertTrue(client.getIssuer().equals("https://identity.example.com"));
        assertTrue(client.getClientId().equals("client-id"));
        assertTrue(client.getRedirectUri().equals("com.example.app:/oauth/callback"));
        assertTrue(request.getUrl().contains("response_type=code"));
        assertTrue(request.getCodeVerifier().equals("code-verifier"));
        assertTrue(AceID.class.getMethod("getAccount", android.content.Context.class) != null);
        assertTrue(AceID.class.getMethod("getSessionState", android.content.Context.class, long.class) != null);
        assertTrue(AceID.class.getMethod("getAccountAsync", android.content.Context.class, kotlin.coroutines.Continuation.class) != null);
        assertTrue(AceID.class.getMethod("getValidAccessTokenAsync", android.content.Context.class, long.class, kotlin.coroutines.Continuation.class) != null);
        try {
            AceID.class.getMethod("createClient", android.content.Context.class);
            throw new AssertionError("Android AAR must not expose client provisioning");
        } catch (NoSuchMethodException expected) {
            // Expected: provisioning is outside the AAR boundary.
        }
        try {
            AceID.class.getMethod("createApplication", android.content.Context.class);
            throw new AssertionError("Android AAR must not expose application provisioning");
        } catch (NoSuchMethodException expected) {
            // Expected: provisioning is outside the AAR boundary.
        }
        try {
            AceID.class.getMethod("createProgram", android.content.Context.class);
            throw new AssertionError("Android AAR must not expose program provisioning");
        } catch (NoSuchMethodException expected) {
            // Expected: provisioning is outside the AAR boundary.
        }
    }
}
