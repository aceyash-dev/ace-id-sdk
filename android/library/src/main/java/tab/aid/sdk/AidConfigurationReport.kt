package tab.aid.sdk

data class AidConfigurationCheck(
    val name: String,
    val passed: Boolean,
    val detail: String? = null,
)

data class AidConfigurationReport(
    val checks: List<AidConfigurationCheck>,
) {
    val isValid: Boolean get() = checks.all(AidConfigurationCheck::passed)
}
