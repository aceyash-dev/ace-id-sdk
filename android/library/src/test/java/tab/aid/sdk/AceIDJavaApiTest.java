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

        AuthorizationRequest request = client.createAuthorizationRequest(configuration);

        assertTrue(request.getUrl().contains("code_challenge_method=S256"));
        assertTrue(request.getCodeVerifier().length() >= 43);
    }
}
