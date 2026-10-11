package tab.aid.sdk

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URI
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.RSAPublicKeySpec

internal object AidJwtVerifier {
    internal const val MAX_ID_TOKEN_BYTES = 131_072
    private const val MAX_JWKS_BYTES = 1_000_000
    private const val CLOCK_SKEW_SECONDS = 60L

    fun verify(
        jwt: String,
        configuration: OidcConfiguration,
        clientId: String,
        nonce: String? = null,
        maxAgeSeconds: Long? = null,
    ): AidUser {
        validateTokenSize(jwt)
        val parts = jwt.split('.')
        if (parts.size != 3) throw AidException("ID token is not a valid JWT")

        val header = parseJson(decode(parts[0]).toString(Charsets.UTF_8), "ID token header")
        val claims = parseJson(decode(parts[1]).toString(Charsets.UTF_8), "ID token claims")
        val signature = decode(parts[2])

        val algorithm = header.optString("alg")
        val kid = header.optString("kid").takeIf { it.isNotBlank() }
        if (header.has("crit") || (header.has("b64") && header.opt("b64") != true)) {
            throw AidException("Unsupported critical ID token header")
        }
        if (algorithm !in setOf("RS256", "RS384", "RS512")) {
            throw AidException("Unsupported ID token signing algorithm: " + algorithm)
        }
        if (header.has("kid") && (header.opt("kid") !is String || kid == null)) {
            throw AidException("ID token kid header must be a non-empty string")
        }
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
        validateIssuedAtAndAuthorizedParty(claims, clientId)
        if (maxAgeSeconds != null) validateAuthenticationTime(claims, maxAgeSeconds)

        validateTimeClaims(claims)

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

    internal fun validateTokenSize(jwt: String) {
        if (jwt.toByteArray(Charsets.UTF_8).size > MAX_ID_TOKEN_BYTES) {
            throw AidException("ID token exceeds the supported size limit")
        }
    }

    internal fun validateTimeClaims(
        claims: JSONObject,
        nowSeconds: Long = System.currentTimeMillis() / 1000L,
    ) {
        val expiration = claims.opt("exp") as? Number
            ?: throw AidException("ID token is missing a valid exp claim")
        val expirationSeconds = expiration.toDouble()
        if (!expirationSeconds.isFinite() || expirationSeconds < nowSeconds - CLOCK_SKEW_SECONDS) {
            throw AidException("ID token is expired or has an invalid exp claim")
        }
        if (claims.has("nbf")) {
            val notBefore = claims.opt("nbf") as? Number
                ?: throw AidException("ID token has an invalid nbf claim")
            val notBeforeSeconds = notBefore.toDouble()
            if (!notBeforeSeconds.isFinite() || notBeforeSeconds > nowSeconds + CLOCK_SKEW_SECONDS) {
                throw AidException("ID token is not valid yet")
            }
        }
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
            if (candidate.has("key_ops")) {
                val operations = candidate.optJSONArray("key_ops") ?: continue
                if ((0 until operations.length()).none { operations.optString(it) == "verify" }) continue
            }

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
            val modulusValue = BigInteger(1, decode(modulus))
            val exponentValue = BigInteger(1, decode(exponent))
            if (modulusValue.bitLength() < 2048 || exponentValue < BigInteger.valueOf(3L) ||
                !exponentValue.testBit(0)) {
                throw AidException("JWKS RSA signing key is too weak")
            }
            KeyFactory.getInstance("RSA").generatePublic(
                RSAPublicKeySpec(modulusValue, exponentValue),
            )
        } catch (e: Exception) {
            throw AidException("Failed to construct JWKS RSA public key", e)
        }
    }

    private fun fetch(url: String): JSONObject {
        val uri = try {
            URI(url)
        } catch (e: Exception) {
            throw AidException("Invalid OIDC JWKS URL", e)
        }
        val scheme = uri.scheme?.lowercase()
        val host = uri.host?.lowercase()
        val loopback = host == "localhost" || host == "127.0.0.1" || host == "::1"
        if (uri.userInfo != null || uri.fragment != null ||
            (scheme != "https" && !(scheme == "http" && loopback))) {
            throw AidException("OIDC JWKS URL must use HTTPS and contain no credentials or fragment")
        }
        val connection = try {
            uri.toURL().openConnection() as HttpURLConnection
        } catch (e: Exception) {
            throw AidException("Failed to open OIDC JWKS URL", e)
        }

        try {
            connection.requestMethod = "GET"
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.setRequestProperty("Accept", "application/json")
            if (connection.responseCode !in 200..299) {
                throw AidException("JWKS request failed: HTTP " + connection.responseCode)
            }
            val json = connection.inputStream.use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size() + count > MAX_JWKS_BYTES) {
                        throw AidException("JWKS response exceeds the supported size limit")
                    }
                    output.write(buffer, 0, count)
                }
                output.toString(Charsets.UTF_8.name())
            }
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

    internal fun validateAuthenticationTime(
        claims: JSONObject,
        maxAgeSeconds: Long,
        nowSeconds: Long = System.currentTimeMillis() / 1000L,
    ) {
        if (maxAgeSeconds < 0L) throw AidException("Requested max_age must be non-negative")
        val authTime = claims.opt("auth_time") as? Number
            ?: throw AidException("ID token is missing auth_time required by max_age")
        val authTimeSeconds = authTime.toDouble()
        if (!authTimeSeconds.isFinite() || authTimeSeconds > nowSeconds + CLOCK_SKEW_SECONDS ||
            nowSeconds - authTimeSeconds > maxAgeSeconds.toDouble() + CLOCK_SKEW_SECONDS) {
            throw AidException("ID token authentication time exceeds the requested max_age")
        }
    }

    internal fun validateIssuedAtAndAuthorizedParty(
        claims: JSONObject,
        clientId: String,
        nowSeconds: Long = System.currentTimeMillis() / 1000L,
    ) {
        val issuedAt = claims.opt("iat") as? Number
            ?: throw AidException("ID token is missing a valid iat claim")
        val issuedAtSeconds = issuedAt.toDouble()
        if (!issuedAtSeconds.isFinite() || issuedAtSeconds > nowSeconds + CLOCK_SKEW_SECONDS) {
            throw AidException("ID token iat claim is invalid or in the future")
        }

        val authorizedParty = if (claims.has("azp")) claims.optString("azp") else null
        if (authorizedParty != null && authorizedParty != clientId) {
            throw AidException("ID token authorized party does not match this client")
        }
        val audience = claims.opt("aud")
        if (audience is JSONArray && audience.length() > 1 && authorizedParty != clientId) {
            throw AidException("ID token with multiple audiences must identify this client as authorized party")
        }
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
        if (value.isEmpty() || value.length % 4 == 1 || value.any {
                it !in 'A'..'Z' && it !in 'a'..'z' && it !in '0'..'9' && it != '-' && it != '_'
            }) {
            throw AidException("Invalid base64url encoding")
        }
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
