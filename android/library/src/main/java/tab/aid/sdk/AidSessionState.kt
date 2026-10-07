package tab.aid.sdk

sealed class AidSessionState {
    data object Unauthenticated : AidSessionState()
    data class Authenticated(val session: AidSession) : AidSessionState()
    data class Expired(val session: AidSession) : AidSessionState()
}
