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
    }
}
