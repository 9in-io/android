package io.ninein.android

/**
 * The tokens of the signed-in user. [toString] never prints them.
 *
 * @property expiresAtMillis when the access token expires (epoch milliseconds, device clock).
 * @property refreshToken rotated by 9in on every refresh; the SDK always keeps the newest one.
 */
public class Credentials(
    public val accessToken: String,
    public val tokenType: String,
    public val expiresAtMillis: Long,
    public val refreshToken: String?,
    public val idToken: String?,
    public val scope: String?,
    /** When the tokens were obtained (epoch milliseconds, device clock); 0 when unknown. */
    public val obtainedAtMillis: Long = 0,
) {
    /** True when the access token expires within [leewaySeconds] (at [nowMillis]). */
    @JvmOverloads
    public fun isExpired(leewaySeconds: Long = 0, nowMillis: Long = System.currentTimeMillis()): Boolean =
        expiresAtMillis - leewaySeconds * 1000 <= nowMillis

    /** The granted scopes. */
    public val scopes: List<String> get() = scope?.split(' ')?.filter { it.isNotEmpty() } ?: emptyList()

    override fun toString(): String =
        "Credentials(tokenType=$tokenType, expiresAtMillis=$expiresAtMillis, scope=$scope, refreshToken=${if (refreshToken != null) "…" else "null"}, idToken=${if (idToken != null) "…" else "null"})"

    internal fun toJson(): String = Json.stringify(
        mapOf(
            "access_token" to accessToken,
            "token_type" to tokenType,
            "expires_at" to expiresAtMillis,
            "refresh_token" to refreshToken,
            "id_token" to idToken,
            "scope" to scope,
            "obtained_at" to obtainedAtMillis,
        ),
    )

    internal companion object {
        fun fromJson(text: String): Credentials? {
            val json = try {
                Json.parseObject(text)
            } catch (e: NineException) {
                return null
            }
            return Credentials(
                accessToken = json.string("access_token") ?: return null,
                tokenType = json.string("token_type") ?: "Bearer",
                expiresAtMillis = json.long("expires_at") ?: 0,
                refreshToken = json.string("refresh_token"),
                idToken = json.string("id_token"),
                scope = json.string("scope"),
                obtainedAtMillis = json.long("obtained_at") ?: 0,
            )
        }

        /** From a token endpoint response; missing refresh and ID tokens are taken from [previous]. */
        fun fromTokenResponse(json: Map<String, Any?>, nowMillis: Long, previous: Credentials? = null): Credentials {
            val accessToken = json.string("access_token")?.takeIf { it.isNotEmpty() }
                ?: throw NineException(NineException.INVALID_RESPONSE, "no access_token in the token response")
            val expiresIn = json.long("expires_in") ?: 3600
            return Credentials(
                accessToken = accessToken,
                tokenType = json.string("token_type") ?: "Bearer",
                expiresAtMillis = nowMillis + expiresIn * 1000,
                refreshToken = json.string("refresh_token") ?: previous?.refreshToken,
                idToken = json.string("id_token") ?: previous?.idToken,
                scope = json.string("scope") ?: previous?.scope,
                obtainedAtMillis = nowMillis,
            )
        }
    }
}

/** A sign-in that was started: what the callback is checked against. Single use. */
internal class PendingLogin(
    val state: String,
    val nonce: String,
    val verifier: String,
    val redirectUri: String,
    val createdAtMillis: Long,
) {
    fun toJson(): String = Json.stringify(
        mapOf("state" to state, "nonce" to nonce, "verifier" to verifier, "redirect_uri" to redirectUri, "created_at" to createdAtMillis),
    )

    companion object {
        fun fromJson(text: String): PendingLogin? {
            val json = try {
                Json.parseObject(text)
            } catch (e: NineException) {
                return null
            }
            return PendingLogin(
                state = json.string("state") ?: return null,
                nonce = json.string("nonce") ?: return null,
                verifier = json.string("verifier") ?: return null,
                redirectUri = json.string("redirect_uri") ?: return null,
                createdAtMillis = json.long("created_at") ?: return null,
            )
        }
    }
}

/** The signed-in user: the verified claims of the ID token. */
public class NineUser(
    /** Every claim, as JSON values (`String`, `Long`, `Double`, `Boolean`, `List`, `Map`, `null`). */
    public val claims: Map<String, Any?>,
) {
    /** The user's ID at 9in (`sub`). */
    public val id: String get() = claims["sub"] as? String ?: ""
    public val email: String? get() = claims["email"] as? String
    public val emailVerified: Boolean? get() = claims["email_verified"] as? Boolean
    public val name: String? get() = claims["name"] as? String
    public val givenName: String? get() = claims["given_name"] as? String
    public val familyName: String? get() = claims["family_name"] as? String
    public val picture: String? get() = claims["picture"] as? String
    public val phoneNumber: String? get() = claims["phone_number"] as? String
    public val locale: String? get() = claims["locale"] as? String

    /** How the user signed in (`pwd`, `otp`, `social`, `fed`, `link`, `mfa`). */
    @Suppress("UNCHECKED_CAST")
    public val authenticationMethods: List<String> get() = (claims["amr"] as? List<Any?>)?.filterIsInstance<String>() ?: emptyList()

    public operator fun get(claim: String): Any? = claims[claim]

    override fun equals(other: Any?): Boolean = other is NineUser && other.claims == claims
    override fun hashCode(): Int = claims.hashCode()
    override fun toString(): String = "NineUser(id=$id, email=$email)"
}
