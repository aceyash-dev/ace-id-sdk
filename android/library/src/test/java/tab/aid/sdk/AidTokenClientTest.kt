package tab.aid.sdk

import org.junit.Assert.fail
import org.junit.Test

class AidTokenClientTest {
    @Test
    fun userInfoRejectsInsecureRemoteEndpoint() {
        try {
            AidTokenClient.fetchUserInfo("http://example.com/userinfo", "access-token")
            fail("Expected insecure userinfo endpoint to be rejected")
        } catch (expected: AidException) {
            // Expected: remote UserInfo must use HTTPS.
        }
    }

    @Test
    fun userInfoRejectsBlankAccessToken() {
        try {
            AidTokenClient.fetchUserInfo("https://example.com/userinfo", "")
            fail("Expected blank access token to be rejected")
        } catch (expected: AidException) {
            // Expected: account reads require an access token.
        }
    }
}
