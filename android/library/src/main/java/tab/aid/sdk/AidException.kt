package tab.aid.sdk

open class AidException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

class AidDiscoveryException(
    message: String,
    cause: Throwable? = null,
) : AidException(message, cause)

class AidConfigurationException(
    message: String,
) : AidException(message)


/** OAuth token endpoint error with a machine-readable provider error code. */
class AidTokenEndpointException(
    val errorCode: String?,
    message: String,
    cause: Throwable? = null,
) : AidException(message, cause)
