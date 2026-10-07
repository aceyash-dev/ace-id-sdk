package tab.aid.sdk

sealed interface AidSessionState {
    data object Unauthenticated : AidSessionState
    data class Authenticated(val account: AidUser) : AidSessionState
    data object Expired : AidSessionState
}
