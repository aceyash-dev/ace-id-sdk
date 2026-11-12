package tab.aid.sdk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
    }

    @Test
    public void javaCanConfigureNetworkPolicy() {
        AceID client = new AceID(
            "https://identity.example.com",
            "client-id",
            "com.example.app:/oauth/callback",
            "openid profile email",
            6L * 60L * 60L * 1000L,
            30_000L,
            60L,
            AidNetworkPolicy.standard()
        );

        assertEquals(2, client.getNetworkPolicy().getMaxRetries());
        assertEquals(10_000, client.getNetworkPolicy().getConnectTimeoutMs());
        assertTrue(client.getNetworkPolicy().isRetryableStatus(503));
        assertFalse(client.getNetworkPolicy().isRetryableStatus(401));
    }

    @Test
    public void javaCanBuildABiometricOptionsValue() {
        AidBiometricOptions options = new AidBiometricOptions(
            "Unlock Ace ID",
            "Confirm it is you",
            "Your session is stored on this device",
            "Use password",
            false
        );

        assertEquals("Unlock Ace ID", options.getTitle());
        assertTrue(AidBiometricResult.Succeeded.INSTANCE.isSuccess());
    }
}
