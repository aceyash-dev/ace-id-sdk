package tab.aid.sdk

import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URI
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.RSAPublicKeySpec

internal object AidJwtVerifier {
    private const val CLOCK_SKEW_SECONDS = 60L

    fun verify(
        jwt: String,
        configuration: OidcConfiguration,
        clientId: String,
        nonce: String? = null,
    ): AidUser {
        val parts = jwt.split('.')
        if (parts.size != 3) throw AidException("ID token is not a valid JWT")

        val header = parseJson(decode(parts[0]), "ID token header")
        val claims = parseJson(decode(parts[1]), "ID token claims")
        val signature = decode(parts[2])

        val algorithm = header.optString("alg")
        val kid = header.optString("kid").takeIf { it.isNotBlank() }
        val signingInput = (parts[0] + "." + parts[1]).toByteArray(Charsets.US_ASCII)

        val key = findKey(configuration.jwksUri, kid, algorithm)
        val verifier = Signature.getInstance(signatureAlgorithm(algorithm))
        verifier.initVerify(key)
        verifier.update(signingInput)
        if (!verifier.verify(signature)) {
            throw AidException("ID token signature verification failed")
        }

        val issuer = claims.optString("iss")
        if (issuer != configuration.issuer) {
            throw AidException("ID token issuer does not match the configured issuer")
        }

        if (!audienceContains(claims.opt("aud"), clientId)) {
            throw AidException("ID token audience does not contain this client")
        }

        val now = System.currentTimeMillis() / 1000L
        val expiresAt = claims.optLong("exp", Long.MIN_VALUE)
        if (expiresAt == Long.MIN_VALUE || expiresAt < now - CLOCK_SKEW_SECONDS) {
            throw AidException("ID token is expired or missing exp")
        }

        val subject = claims.optString("sub")
        if (subject.isBlank()) throw AidException("ID token is missing sub")

        if (nonce != null && claims.optString("nonce") != nonce) {
            throw AidException("ID token nonce does not match the authorization transaction")
        }

        return AidUser(
            subject = subject,
            claims = jsonObjectToMap(claims),
        )
    }

    private fun findKey(
        jwksUri: String?,
        kid: String?,
        algorithm: String,
    ): java.security.PublicKey {
        if (jwksUri.isNullOrBlank()) {
            throw AidDiscoveryException("OIDC discovery document is missing jwks_uri")
        }

        val response = fetch(jwksUri)
        val keys = response.optJSONArray("keys") ?: throw AidException("JWKS is missing keys")

        var fallback: JSONObject? = null
        for (i in 0 until keys.length()) {
            val candidate = keys.optJSONObject(i) ?: continue
            if (candidate.optString("kty") != "RSA") continue
            if (candidate.optString("use").isNotBlank() && candidate.optString("use") != "sig") continue
            if (candidate.optString("alg").isNotBlank() && candidate.optString("alg") != algorithm) continue

            val candidateKid = candidate.optString("kid").takeIf { it.isNotBlank() }
            if (kid != null && candidateKid == kid) return rsaKey(candidate)
            if (kid == null && fallback == null) fallback = candidate
        }

        if (fallback != null) return rsaKey(fallback)
        throw AidException("No suitable JWKS signing key found for ID token")
    }

    private fun rsaKey(jwk: JSONObject): java.security.PublicKey {
        val modulus = jwk.optString("n")
        val exponent = jwk.optString("e")
        if (modulus.isBlank() || exponent.isBlank()) {
            throw AidException("JWKS RSA key is missing n or e")
        }

        return try {
            KeyFactory.getInstance("RSA").generatePublic(
                RSAPublicKeySpec(
                    BigInteger(1, decode(modulus)),
                    BigInteger(1, decode(exponent)),
                ),
            )
        } catch (e: Exception) {
            throw AidException("Failed to construct JWKS RSA public key", e)
        }
    }

    private fun fetch(url: String): JSONObject {
        val connection = try {
            URI(url).toURL().openConnection() as HttpURLConnection
        } catch (e: Exception) {
            throw AidException("Failed to open OIDC JWKS URL", e)
        }

        try {
            connection.requestMethod = "GET"
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.setRequestProperty("Accept", "application/json")
            if (connection.responseCode !in 200..299) {
                throw AidException("JWKS request failed: HTTP " + connection.responseCode)
            }
            val json = connection.inputStream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            return parseJson(json, "JWKS")
        } catch (e: AidException) {
            throw e
        } catch (e: Exception) {
            throw AidException("Failed to fetch OIDC JWKS", e)
        } finally {
            connection.disconnect()
        }
    }

    private fun signatureAlgorithm(algorithm: String): String = when (algorithm) {
        "RS256" -> "SHA256withRSA"
        "RS384" -> "SHA384withRSA"
        "RS512" -> "SHA512withRSA"
        else -> throw AidException("Unsupported ID token signing algorithm: " + algorithm)
    }

    private fun audienceContains(value: Any?, clientId: String): Boolean = when (value) {
        is String -> value == clientId
        is JSONArray -> (0 until value.length()).any { value.optString(it) == clientId }
        else -> false
    }

    private fun parseJson(value: String, description: String): JSONObject =
        try {
            JSONObject(value)
        } catch (e: Exception) {
            throw AidException(description + " is not valid JSON", e)
        }

    private fun jsonObjectToMap(value: JSONObject): Map<String, Any?> {
        val result = linkedMapOf<String, Any?>()
        val iterator = value.keys()
        while (iterator.hasNext()) {
            val key = iterator.next()
            result[key] = jsonValueToKotlin(value.opt(key))
        }
        return result
    }

    private fun jsonValueToKotlin(value: Any?): Any? = when (value) {
        null, JSONObject.NULL -> null
        is JSONObject -> jsonObjectToMap(value)
        is JSONArray -> (0 until value.length()).map { jsonValueToKotlin(value.opt(it)) }
        else -> value
    }

    private fun decode(value: String): ByteArray {
        val normalized = value.replace('-', '+').replace('_', '/')
        val padded = normalized + "=".repeat((4 - normalized.length % 4) % 4)
        if (padded.any { it.isWhitespace() }) throw AidException("Invalid base64url encoding")
        return try {
            val output = java.io.ByteArrayOutputStream()
            var buffer = 0
            var bits = 0
            for (char in padded) {
                if (char == '=') break
                val digit = base64Digit(char)
                buffer = (buffer shl 6) or digit
                bits += 6
                if (bits >= 8) {
                    bits -= 8
                    output.write((buffer shr bits) and 0xff)
                }
            }
            output.toByteArray()
        } catch (e: AidException) {
            throw e
        } catch (e: Exception) {
            throw AidException("Invalid base64url encoding", e)
        }
    }

    private fun base64Digit(char: Char): Int = when (char) {
        in 'A'..'Z' -> char.code - 'A'.code
        in 'a'..'z' -> char.code - 'a'.code + 26
        in '0'..'9' -> char.code - '0'.code + 52
        '+' -> 62
        '/' -> 63
        else -> throw AidException("Invalid base64url character")
    }
}
