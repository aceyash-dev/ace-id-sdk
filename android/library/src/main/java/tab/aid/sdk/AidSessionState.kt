package tab.aid.sdk

/**
 * Observable authentication state.
 *
 * `Unauthenticated` means "no session"; `Expired` means "a session exists but its
 * access token is stale"; `RefreshFailed` means "a session exists, the SDK tried
 * to extend it, and the attempt failed". Applications usually answer the first
 * three differently — a login screen, a silent refresh, and a "please sign in
 * again" prompt — so they are distinct states rather than one nullable session.
 */
sealed interface AidSessionState {
    /** No session is stored. */
    data object Unauthenticated : AidSessionState

    /** A session exists and its access token is usable. */
    data class Authenticated(val account: AidUser) : AidSessionState

    /** A session exists but its access token is expired; refresh is required. */
    data object Expired : AidSessionState

    /**
     * A refresh was attempted and failed.
     *
     * The stored session is not discarded unless the provider rejected the
     * refresh token (`invalid_grant`), in which case the SDK moves to
     * [Unauthenticated] instead.
     */
    data class RefreshFailed(val error: Throwable) : AidSessionState
}
