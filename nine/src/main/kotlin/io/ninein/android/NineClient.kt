package io.ninein.android

import android.content.Context
import io.ninein.AuthClient
import io.ninein.PendingLogin
import io.ninein.TokenSet
import io.ninein.http.HttpTransport
import io.ninein.http.UrlConnectionTransport
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.time.Clock
import java.time.Duration

/**
 * Sign-in for Android apps with 9in: authorization code flow with PKCE in Custom Tabs, tokens
 * encrypted with an Android Keystore key, refresh with rotation, sign-out. The protocol (discovery,
 * PKCE, the redirect and ID token checks, token requests) is the Java SDK's [AuthClient]; this class
 * adds the browser, storage, coroutines and state.
 *
 * ```
 * val nine = NineClient(context, issuer = "https://acme.9in.io", clientId = "app_…", redirectUri = "com.acme.app:/callback")
 * val user = nine.signIn(activity)          // Custom Tab, PKCE, state, nonce, ID token checks
 * val token = nine.accessToken()            // refreshed (and rotated) when it is about to expire
 * nine.signOut(activity)                    // revokes the refresh token, ends the 9in session
 * ```
 *
 * Create one per app (for example in your `Application` or with your DI framework) and share it:
 * it is safe to use from any thread, and concurrent [accessToken] calls share one refresh.
 * [state] tells you who is signed in, for Compose (`collectAsState()`) or any other UI.
 */
public class NineClient internal constructor(
    public val config: NineConfig,
    private val store: CredentialStore,
    http: HttpTransport,
    private val io: CoroutineDispatcher,
    private val clock: Clock,
) {
    /** A client that keeps its tokens in [store] (any platform; see [MemoryCredentialStore]). */
    @JvmOverloads
    public constructor(config: NineConfig, store: CredentialStore, http: HttpTransport = UrlConnectionTransport()) :
        this(config, store, http, Dispatchers.IO, Clock.systemUTC())

    /** A client that keeps its tokens encrypted with an Android Keystore key ([KeystoreCredentialStore]). */
    @JvmOverloads
    public constructor(context: Context, config: NineConfig, http: HttpTransport = UrlConnectionTransport()) :
        this(config, KeystoreCredentialStore(context), http)

    /**
     * A client for [issuer] and the application [clientId], with tokens in the Android Keystore.
     *
     * @param redirectUri the callback registered on the application, e.g. `com.acme.app:/callback`
     *   (with `manifestPlaceholders["nineRedirectScheme"] = "com.acme.app"`).
     * @param audience an API identifier, to get access tokens for your API.
     */
    @JvmOverloads
    public constructor(
        context: Context,
        issuer: String,
        clientId: String,
        redirectUri: String,
        audience: String? = null,
        scopes: List<String> = NineConfig.DEFAULT_SCOPES,
    ) : this(context, NineConfig(issuer, clientId, redirectUri, scopes, audience))

    /** The Java SDK client that speaks the protocol (blocking calls: always on [io]). */
    internal val auth: AuthClient = config.authClient(userAgent(http), clock)
    private val scope = CoroutineScope(SupervisorJob() + io)
    private val keyPrefix = "9in:${config.issuer}:${config.clientId}"
    private val credentialsKey = "$keyPrefix:credentials"
    private val pendingKey = "$keyPrefix:pending"
    private val obtainedKey = "$keyPrefix:obtained_at"

    private val lock = Any()
    private val loaded = CompletableDeferred<Unit>()
    private val signInLock = Mutex()
    private val refreshLock = Mutex()

    @Volatile private var credentials: Credentials? = null
    @Volatile private var pending: PendingLogin? = null

    private val mutableState = MutableStateFlow<AuthState>(AuthState.Loading)

    /** Who is signed in. Starts as [AuthState.Loading] while the stored session is read. */
    public val state: StateFlow<AuthState> = mutableState.asStateFlow()

    /** The signed-in user (the ID token's verified claims), or null. */
    public val user: NineUser? get() = (mutableState.value as? AuthState.SignedIn)?.user

    /** True when a user is signed in (a valid access token or a refresh token is stored). */
    public val isSignedIn: Boolean get() = mutableState.value is AuthState.SignedIn

    init {
        scope.launch { load() }
    }

    private fun load() {
        try {
            val stored = store.read(credentialsKey)?.let { readTokens(it) }?.let {
                Credentials(it, store.read(obtainedKey)?.toLongOrNull() ?: 0)
            }
            pending = store.read(pendingKey)?.let { readPending(it) }
            if (stored != null && (stored.refreshToken != null || !stored.isExpired(0, clock.millis()))) {
                credentials = stored
                mutableState.value = AuthState.SignedIn(NineUser(stored.tokenSet.claims()))
            } else {
                if (stored != null) {
                    store.write(credentialsKey, null)
                    store.write(obtainedKey, null)
                }
                mutableState.value = AuthState.SignedOut
            }
        } catch (e: Exception) {
            // An unreadable store (a lost Keystore key, corrupt data) means nobody is signed in.
            credentials = null
            mutableState.value = AuthState.SignedOut
        } finally {
            loaded.complete(Unit)
        }
        AuthorizationBroker.register(this)
    }

    private suspend fun awaitLoaded() = loaded.await()

    // ---------------------------------------------------------------------------------------------
    // Sign-in

    /**
     * Signs the user in: opens the hosted sign-in page in a Custom Tab (or the browser), waits for
     * the redirect, checks it (state, issuer), exchanges the code with the PKCE verifier, verifies
     * the ID token and stores the tokens. Returns the signed-in user.
     *
     * @param context an Activity (or a context that wraps one, such as Compose's `LocalContext`).
     * @throws NineException [NineException.CANCELED] when the user closes the browser, an OAuth
     *   error such as [NineException.ACCESS_DENIED], or a failed check.
     */
    @JvmOverloads
    public suspend fun signIn(context: Context, options: SignInOptions = SignInOptions()): NineUser =
        signIn(CustomTabsBrowser(context), options)

    /** Opens the sign-up form directly (`prompt=create`); otherwise the same as [signIn]. */
    @JvmOverloads
    public suspend fun signUp(context: Context, options: SignInOptions = SignInOptions()): NineUser =
        signUp(CustomTabsBrowser(context), options)

    /** [signIn] with your own [BrowserStep] (tests, other platforms). */
    public suspend fun signIn(browser: BrowserStep, options: SignInOptions = SignInOptions()): NineUser =
        authorize(browser, options, signUp = false)

    /** [signUp] with your own [BrowserStep]. */
    public suspend fun signUp(browser: BrowserStep, options: SignInOptions = SignInOptions()): NineUser =
        authorize(browser, options, signUp = true)

    private suspend fun authorize(browser: BrowserStep, options: SignInOptions, signUp: Boolean): NineUser {
        awaitLoaded()
        val login = withContext(io) {
            core { auth.createLogin(options.toLoginOptions(config, signUp)) }.also { savePending(it.pending()) }
        }
        val callback = try {
            browser.open(login.url(), config.redirectUri)
        } catch (e: NineException) {
            if (e.code == NineException.CANCELED) withContext(io) { clearPending(login.pending().state()) }
            throw e
        }
        // Once 9in has redirected back, finish even if the caller goes away (a rotation, say):
        // the code is single-use, and [state] tells the UI the outcome.
        return withContext(NonCancellable) { handleRedirect(callback) }
    }

    /**
     * Completes a sign-in from the redirect URL 9in sent the browser to. [signIn] calls this
     * itself; call it when your app receives the redirect some other way (your own activity for an
     * App Link, say). The redirect must belong to the sign-in in progress (`state`), and is
     * accepted only once.
     */
    public suspend fun handleRedirect(url: String): NineUser {
        awaitLoaded()
        return withContext(io) {
            signInLock.withLock {
                val current = pending
                // The redirect must belong to the sign-in in progress before anything in it counts,
                // even an error: another app can send this activity any URL with our scheme.
                if (current == null) throw NineException(NineException.INVALID_STATE, "no sign-in in progress")
                if (!matchesState(url, current)) throw NineException(NineException.INVALID_STATE, "state mismatch")
                // Single use: a redirect for this sign-in consumes it, whatever the outcome.
                clearPending(current.state())
                val tokens = core { auth.handleCallback(url, current) }
                val obtained = clock.millis()
                val user = NineUser(tokens.claims())
                // After any refresh of the previous session, so its result can't overwrite this one.
                refreshLock.withLock { saveCredentials(Credentials(tokens, obtained), user) }
                user
            }
        }
    }

    /**
     * Called by the Android redirect handling when a redirect arrives that nobody is waiting for
     * (the caller was cancelled, or the process was restarted while the browser was open).
     */
    internal fun offerRedirect(url: String): Boolean {
        val current = pending ?: return false
        if (!matchesState(url, current)) return false
        scope.launch {
            try {
                handleRedirect(url)
            } catch (e: NineException) {
                // Nobody is waiting for this sign-in; [state] stays as it was.
            }
        }
        return true
    }

    // ---------------------------------------------------------------------------------------------
    // Tokens

    /**
     * A valid access token. When it expires within [minValiditySeconds], it is refreshed first
     * (9in rotates the refresh token; the new one is stored). Concurrent callers share one refresh.
     *
     * @throws NineException [NineException.LOGIN_REQUIRED] when nobody is signed in, or the session
     *   ended (the user is then signed out); [NineException.NETWORK_ERROR] when 9in can't be
     *   reached (the session is kept).
     */
    @JvmOverloads
    public suspend fun accessToken(minValiditySeconds: Long = 60): String {
        awaitLoaded()
        credentials?.let { if (!it.isExpired(it.margin(minValiditySeconds), clock.millis())) return it.accessToken }
        return refreshLock.withLock {
            val current = credentials ?: throw NineException(NineException.LOGIN_REQUIRED, "nobody is signed in")
            if (!current.isExpired(current.margin(minValiditySeconds), clock.millis())) return@withLock current.accessToken
            if (current.refreshToken == null) {
                // Nothing to refresh with: the token is good until it actually expires.
                if (!current.isExpired(0, clock.millis())) return@withLock current.accessToken
                withContext(io) { clearSession() }
                throw NineException(NineException.LOGIN_REQUIRED, "the access token expired and there is no refresh token (request offline_access)")
            }
            withContext(NonCancellable + io) { refreshNow(current) }.accessToken
        }
    }

    /** At most half the token's lifetime, so short-lived tokens aren't refreshed on every call. */
    private fun Credentials.margin(minValiditySeconds: Long): Long {
        val lifetime = (expiresAtMillis - obtainedAtMillis) / 1000
        return if (obtainedAtMillis > 0 && lifetime > 0) minOf(minValiditySeconds, lifetime / 2) else minValiditySeconds
    }

    /** Refreshes the tokens now, whether or not the access token is about to expire. */
    public suspend fun refresh(): Credentials {
        awaitLoaded()
        return refreshLock.withLock {
            val current = credentials ?: throw NineException(NineException.LOGIN_REQUIRED, "nobody is signed in")
            if (current.refreshToken == null) throw NineException(NineException.LOGIN_REQUIRED, "there is no refresh token (request offline_access)")
            withContext(NonCancellable + io) { refreshNow(current) }
        }
    }

    private suspend fun refreshNow(current: Credentials): Credentials {
        try {
            // The core checks a new ID token (same subject) and keeps the old refresh token only
            // when 9in sends none back.
            val tokens = core { auth.refresh(current.tokenSet) }
            val next = Credentials(tokens, clock.millis())
            saveCredentials(next, NineUser(tokens.claims()))
            return next
        } catch (e: NineException) {
            when (e.code) {
                NineException.INVALID_GRANT -> {
                    // Revoked, expired, or the session ended: the user has to sign in again.
                    clearSession()
                    throw NineException(NineException.LOGIN_REQUIRED, "the session ended; sign in again", e.status, e)
                }
                NineException.INVALID_ID_TOKEN -> {
                    clearSession()
                    throw e
                }
                else -> throw e
            }
        }
    }

    /** The stored tokens (the access token may have expired; use [accessToken] for a valid one). */
    public suspend fun credentials(): Credentials? {
        awaitLoaded()
        return credentials
    }

    /** The user's current profile from 9in's userinfo endpoint. */
    public suspend fun userInfo(): Map<String, Any?> {
        val token = accessToken()
        return withContext(io) { core { auth.userInfo(token) } }
    }

    // ---------------------------------------------------------------------------------------------
    // Sign-out

    /**
     * Signs the user out: forgets the tokens, revokes the refresh token and ends the 9in session
     * in the browser (otherwise the next sign-in is instant, as single sign-on).
     *
     * @param postLogoutRedirectUri where 9in sends the browser afterwards, so the Custom Tab closes
     *   by itself: one of the application's **Allowed logout URLs**, such as your redirect URI.
     *   Without it, 9in shows a "You're signed out" page that the user closes.
     */
    @JvmOverloads
    public suspend fun signOut(context: Context, postLogoutRedirectUri: String? = null): Unit =
        signOut(CustomTabsBrowser(context), postLogoutRedirectUri)

    /**
     * Signs the user out. Without a [browser], only in this app: the tokens are forgotten and the
     * refresh token is revoked, but the 9in session in the browser stays.
     */
    @JvmOverloads
    public suspend fun signOut(browser: BrowserStep? = null, postLogoutRedirectUri: String? = null) {
        awaitLoaded()
        val current = withContext(io) {
            refreshLock.withLock { credentials.also { clearSession() } }
        }
        withContext(NonCancellable + io) {
            val token = current?.refreshToken
            try {
                core { if (token != null) auth.revoke(token, "refresh_token") else current?.let { auth.revoke(it.accessToken, "access_token") } }
            } catch (e: NineException) {
                // Signing out never fails because 9in can't be reached; the tokens are gone here.
            }
        }
        if (browser != null) {
            val url = withContext(io) { core { auth.logoutUrl(current?.idToken, postLogoutRedirectUri, null) } }
            try {
                browser.open(url, postLogoutRedirectUri ?: config.redirectUri)
            } catch (e: NineException) {
                if (e.code != NineException.CANCELED) throw e
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Storage

    private fun savePending(login: PendingLogin) = synchronized(lock) {
        persist(pendingKey, login.toJson())
        pending = login
    }

    private fun clearPending(state: String) = synchronized(lock) {
        if (pending?.state() == state) {
            pending = null
            forget(pendingKey)
        }
    }

    private fun saveCredentials(value: Credentials, user: NineUser) = synchronized(lock) {
        // Memory first: after a refresh the old refresh token is spent, so the new one must be kept
        // for this run even if the store fails.
        credentials = value
        mutableState.value = AuthState.SignedIn(user)
        persist(credentialsKey, value.tokenSet.toJson())
        persist(obtainedKey, value.obtainedAtMillis.toString())
    }

    private fun clearSession() = synchronized(lock) {
        credentials = null
        mutableState.value = AuthState.SignedOut
        forget(credentialsKey)
        forget(obtainedKey)
    }

    private fun persist(key: String, value: String) {
        try {
            store.write(key, value)
        } catch (e: Exception) {
            throw NineException(NineException.STORAGE_ERROR, "could not save to the credential store", cause = e)
        }
    }

    /** Deleting is best effort: the session is over in memory either way. */
    private fun forget(key: String) {
        try {
            store.write(key, null)
        } catch (e: Exception) {
            // Nothing better to do; an unreadable leftover is dropped on the next start.
        }
    }

    private fun readTokens(json: String): TokenSet? = try {
        TokenSet.fromJson(json)
    } catch (e: io.ninein.NineException) {
        null
    }

    private fun readPending(json: String): PendingLogin? = try {
        PendingLogin.fromJson(json)
    } catch (e: RuntimeException) {
        null
    }

    /** Whether the redirect's `state` is the pending sign-in's (constant time). */
    private fun matchesState(url: String, login: PendingLogin): Boolean {
        val state = queryParameter(url, "state")?.toByteArray(Charsets.UTF_8) ?: return false
        val expected = login.state().toByteArray(Charsets.UTF_8)
        var diff = state.size xor expected.size
        for (i in 0 until minOf(state.size, expected.size)) diff = diff or (state[i].toInt() xor expected[i].toInt())
        return diff == 0
    }

    internal companion object {
        /** Adds `User-Agent: 9in-android/<version>` to requests that don't name one. */
        fun userAgent(inner: HttpTransport): HttpTransport = HttpTransport { request ->
            if (request.header("User-Agent") != null) {
                inner.send(request)
            } else {
                inner.send(
                    io.ninein.http.HttpRequest.builder()
                        .method(request.method())
                        .url(request.url())
                        .headers(request.headers())
                        .header("User-Agent", "9in-android/${Nine.VERSION}")
                        .body(request.body())
                        .build(),
                )
            }
        }

        /** A query parameter of a redirect URL, decoded (the first one wins). */
        fun queryParameter(url: String, name: String): String? {
            val query = url.substringBefore('#').substringAfter('?', "")
            for (pair in query.split('&')) {
                val eq = pair.indexOf('=')
                val key = if (eq >= 0) pair.substring(0, eq) else pair
                try {
                    if (java.net.URLDecoder.decode(key, "UTF-8") == name) {
                        return if (eq >= 0) java.net.URLDecoder.decode(pair.substring(eq + 1), "UTF-8") else ""
                    }
                } catch (e: IllegalArgumentException) {
                    // A malformed escape: not this parameter.
                }
            }
            return null
        }
    }
}
