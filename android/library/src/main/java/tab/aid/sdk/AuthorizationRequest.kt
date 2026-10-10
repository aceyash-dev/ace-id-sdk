package tab.aid.sdk

/** Optional OIDC hints for step-up and risk-based authentication. */
data class AidAuthorizationOptions(
    val prompt: String? = null,
    val loginHint: String? = null,
    val maxAgeSeconds: Long? = null,
    val acrValues: List<String> = emptyList(),
    val uiLocales: List<String> = emptyList(),
    val additionalParameters: Map<String, String> = emptyMap(),
) {
    init {
        if (prompt != null && (prompt.isBlank() || prompt.any { it.isISOControl() })) {
            throw AidConfigurationException("prompt must be non-empty and contain no control characters")
        }
        if (loginHint != null && (loginHint.isBlank() || loginHint.any { it.isISOControl() })) {
            throw AidConfigurationException("loginHint must be non-empty and contain no control characters")
        }
        if (maxAgeSeconds != null && maxAgeSeconds < 0) throw AidConfigurationException("maxAgeSeconds must be non-negative")
        validateTokens("acrValues", acrValues)
        validateTokens("uiLocales", uiLocales)
        val reserved = setOf(
            "client_id", "redirect_uri", "response_type", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method", "code_verifier", "grant_type",
            "request", "request_uri", "prompt", "login_hint", "max_age", "acr_values", "ui_locales",
        )
        additionalParameters.forEach { (key, value) ->
            if (!key.matches(Regex("^[A-Za-z][A-Za-z0-9_.:-]*$")) || key.lowercase() in reserved) {
                throw AidConfigurationException("additionalParameters cannot override reserved or invalid parameter: $key")
            }
            if (value.isEmpty() || value.any { it.isISOControl() }) {
                throw AidConfigurationException("additionalParameters.$key must be non-empty and contain no control characters")
            }
        }
    }

    private fun validateTokens(name: String, values: List<String>) {
        if (values.any { it.isBlank() || it.any { ch -> ch.isWhitespace() || ch.isISOControl() } }) {
            throw AidConfigurationException("$name must contain non-empty values without whitespace")
        }
    }
}

data class AuthorizationRequest(
    val url: String,
    val state: String,
    val nonce: String,
    val codeVerifier: String,
    val redirectUri: String,
)
