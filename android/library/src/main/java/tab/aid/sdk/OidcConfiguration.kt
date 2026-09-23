package tab.aid.sdk

data class OidcConfiguration(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val userInfoEndpoint: String? = null,
    val jwksUri: String? = null,
    val endSessionEndpoint: String? = null,
    val revocationEndpoint: String? = null,
    val codeChallengeMethodsSupported: List<String> = emptyList(),
    val responseTypesSupported: List<String> = emptyList(),
    val grantTypesSupported: List<String> = emptyList(),
)
