package tab.aid.sdk

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AidSessionStateTest {

    @Test
    fun authenticatedStateCarriesTheAccount() {
        val user = AidUser("sub-1", mapOf("email" to "user@example.test"))
        val state = AidSessionState.Authenticated(user)
        assertEquals("sub-1", state.account.subject)
        assertEquals("user@example.test", state.account.email)
    }

    @Test
    fun refreshFailureKeepsTheCause() {
        val cause = AidException("provider unavailable")
        val state = AidSessionState.RefreshFailed(cause)
        assertEquals(cause, state.error)
        assertFalse(state is AidSessionState.Authenticated)
    }

    @Test
    fun statesAreDistinguishable() {
        val states = listOf<AidSessionState>(
            AidSessionState.Unauthenticated,
            AidSessionState.Expired,
            AidSessionState.RefreshFailed(AidException("x")),
        )
        assertEquals(3, states.toSet().size)
    }

    @Test
    fun biometricResultFlagsSuccess() {
        assertTrue(AidBiometricResult.Succeeded.isSuccess)
        assertFalse(AidBiometricResult.Cancelled.isSuccess)
        assertFalse(AidBiometricResult.Unavailable.isSuccess)
        assertFalse(AidBiometricResult.Failed(1, "locked out").isSuccess)
    }

    @Test
    fun biometricOptionsHaveUsableDefaults() {
        val options = AidBiometricOptions()
        assertTrue(options.title.isNotBlank())
        assertTrue(options.negativeButtonText.isNotBlank())
    }
}
