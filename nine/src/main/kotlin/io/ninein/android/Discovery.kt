package io.ninein.android

/** The parts of the OpenID Connect discovery document the SDK uses. */
public class Discovery internal constructor(
    public val issuer: String,
    public val authorizationEndpoint: String,
    public val tokenEndpoint: String,
    public val jwksUri: String,
    public val userinfoEndpoint: String?,
    public val revocationEndpoint: String?,
    public val endSessionEndpoint: String?,
    /** RFC 9207: the server adds `iss` to every authorization response. */
    public val authorizationResponseIssParameterSupported: Boolean,
    /** The whole document, as JSON values. */
    public val raw: Map<String, Any?>,
) {
    internal companion object {
        fun parse(json: Map<String, Any?>, expectedIssuer: String, allowInsecure: Boolean): Discovery {
            fun required(name: String): String =
                json.string(name)?.takeIf { it.isNotEmpty() } ?: throw NineException(NineException.DISCOVERY_FAILED, "discovery document has no $name")
            fun endpoint(name: String): String = Issuer.checkEndpoint(required(name), expectedIssuer, allowInsecure, name)
            fun optional(name: String): String? = json.string(name)?.takeIf { it.isNotEmpty() }?.let { Issuer.checkEndpoint(it, expectedIssuer, allowInsecure, name) }

            val issuer = required("issuer")
            // OpenID Connect Discovery §4.3: the document must be for the issuer it was fetched from.
            if (!Issuer.same(issuer, expectedIssuer)) {
                throw NineException(NineException.INVALID_ISSUER, "discovery document is for $issuer, not $expectedIssuer")
            }
            return Discovery(
                issuer = issuer.removeSuffix("/"),
                authorizationEndpoint = endpoint("authorization_endpoint"),
                tokenEndpoint = endpoint("token_endpoint"),
                jwksUri = endpoint("jwks_uri"),
                userinfoEndpoint = optional("userinfo_endpoint"),
                revocationEndpoint = optional("revocation_endpoint"),
                endSessionEndpoint = optional("end_session_endpoint"),
                authorizationResponseIssParameterSupported = json["authorization_response_iss_parameter_supported"] == true,
                raw = json,
            )
        }
    }
}
