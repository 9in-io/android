9in Android SDK
===============

<img src="docs/img/logo.png" width="160" alt="9in"/>

Official Android SDK for [9in](https://9in.io): hosted login, OpenID Connect provider and SSO.

`io.ninein.android` signs users in to your Android app with your 9in tenant. It is written in
Kotlin with a coroutine API, and is built on the [9in Java SDK](https://github.com/9in-io/java)
(`com.github.9in-io:java`), whose `AuthClient` speaks the protocol; this library adds the browser,
the redirect, Keystore storage and the state your UI shows. Besides the Java SDK it depends only on
AndroidX Browser and kotlinx-coroutines.

- **Sign users in with Custom Tabs**: the authorization code flow with PKCE (S256), `state`,
  `nonce` and the RFC 9207 `iss` check, in the user's browser, never an embedded web view. Password
  managers work, and the 9in session is shared with the browser (single sign-on).
- **Verified ID tokens**: the signature is checked against your tenant's JWKS with every
  asymmetric algorithm of the 9in key library (RS256/384/512, PS256/384/512, ES256, ES384, and
  EdDSA where Android has it), along with the issuer, audience, expiry and nonce.
- **Tokens encrypted at rest** with AES-256-GCM under a key that stays in the Android Keystore,
  stored outside cloud backups.
- **Fresh access tokens**: `accessToken()` refreshes before expiry with refresh token rotation,
  and concurrent callers share one refresh.
- **Sign-in state as a `StateFlow`**, for Compose or any other UI.
- **Sign-out** that revokes the refresh token and ends the 9in session in the browser.
- **A browser-step interface**, so your tests can run the whole flow without a UI.

Requires Android 8.0 (API 26) or later, Kotlin 2.0 or later, and an app that compiles against
API 34 or later.

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}

// app/build.gradle.kts
dependencies {
    implementation("com.github.9in-io:android:v0.1.0")
}
```

The full guide is [Mobile and desktop apps](https://9in.io/docs/native-apps/) in the 9in docs.

| Building with | Use |
|---|---|
| iOS, macOS (Swift) | [`9in-io/ios`](https://github.com/9in-io/ios) |
| Java on the server, or Android without the UI parts | [`com.github.9in-io:java`](https://github.com/9in-io/java) |
| A back end for your app | [`@9in-io/sdk`](https://github.com/9in-io/sdk) (Node.js), [`9in`](https://github.com/9in-io/python-sdk) (Python), [`9in-io/go-sdk`](https://github.com/9in-io/go-sdk) (Go), [`9in/php-sdk`](https://github.com/9in-io/php-sdk) (PHP) |
| React Native, Flutter | AppAuth-based libraries, see [the guide](https://9in.io/docs/native-apps/) |

## Set up the application

In the 9in console, create an application of type **Native / Mobile**, then add your redirect URI
to **Allowed callback URLs**, and to **Allowed logout URLs** too, so the browser closes by itself
after signing out:

| Redirect URI | When |
|---|---|
| `com.acme.app:/callback` | A private-use scheme: your application ID or another reverse-domain name you own |
| `https://app.acme.com/callback` | An App Link (see [App Links](#app-links)) |

Tell the SDK the scheme in your app's `build.gradle.kts`. It goes into the manifest of the
activity that receives the redirect:

```kotlin
android {
    defaultConfig {
        manifestPlaceholders["nineRedirectScheme"] = "com.acme.app"
    }
}
```

## Sign users in

Create one `NineClient` for your app, for example in your `Application` class or with your
dependency injection framework:

```kotlin
import io.ninein.android.NineClient

class AcmeApp : Application() {
    lateinit var nine: NineClient

    override fun onCreate() {
        super.onCreate()
        nine = NineClient(
            context = this,
            issuer = "https://acme.9in.io",           // or your custom domain
            clientId = "app_7f3k2m9q",
            redirectUri = "com.acme.app:/callback",
            audience = "https://api.acme.com",        // optional: access tokens for your API
        )
    }
}
```

Then sign in from an activity (or anything that has one, like a composable):

```kotlin
lifecycleScope.launch {
    try {
        val user = nine.signIn(this@MainActivity)   // a Custom Tab with the hosted sign-in page
        println("Signed in as ${user.email}")
    } catch (e: NineException) {
        if (e.code != NineException.CANCELED) showError(e.message)
    }
}

nine.signUp(activity)                                // opens the sign-up form (prompt=create)
nine.signIn(activity, SignInOptions(loginHint = "jane@acme.com", prompt = "login"))
```

`signIn` returns once the user is back in your app: the redirect is checked (`state`, `iss`), the
code is exchanged with the PKCE verifier, and the ID token is verified before anything is stored.
A redirect whose `state` doesn't belong to the sign-in in progress is refused before anything in
it counts, since any app can send your redirect scheme a URL.
`user` holds the ID token's claims: `id` (`sub`), `email`, `name`, `picture`, `authenticationMethods`
(`amr`), and every other claim through `user["claim"]`.

If the caller goes away while the browser is open (the activity is recreated, or Android stops your
app's process to free memory), the sign-in still completes when 9in redirects back, and `state`
changes to `SignedIn`.

### Show who is signed in

`nine.state` is a `StateFlow<AuthState>`: `Loading` while the stored session is read at start,
then `SignedOut` or `SignedIn(user)`.

```kotlin
@Composable
fun Account(nine: NineClient) {
    val state by nine.state.collectAsState()
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    when (val s = state) {
        AuthState.Loading -> CircularProgressIndicator()
        AuthState.SignedOut -> Button(onClick = {
            scope.launch {
                try {
                    nine.signIn(context)
                } catch (e: NineException) {
                    if (e.code != NineException.CANCELED) showError(e.message)
                }
            }
        }) { Text("Sign in") }
        is AuthState.SignedIn -> Text("Hello, ${s.user.name}")
    }
}
```

`nine.user` and `nine.isSignedIn` give the current value without collecting.

### Call your API

```kotlin
val token = nine.accessToken()   // refreshed (and rotated) when it expires within a minute
```

Concurrent calls share one refresh, and the new refresh token is stored at once, so a restarted
app never uses a rotated-out token. When the session has ended (the refresh token was revoked or
expired), `accessToken()` throws `NineException` with code `login_required` and the user is signed
out. Network failures throw `network_error` and keep the session.

With OkHttp, an interceptor adds the token to every request (interceptors run on background
threads):

```kotlin
class NineInterceptor(private val nine: NineClient) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val token = runBlocking { nine.accessToken() }
        return chain.proceed(chain.request().newBuilder().header("Authorization", "Bearer $token").build())
    }
}
```

Your API verifies the token with a 9in server SDK (see
[Protecting your API](https://9in.io/docs/protecting-apis/)). Fresh claims from 9in:

```kotlin
val profile: Map<String, Any?> = nine.userInfo()
```

### Sign out

```kotlin
nine.signOut(activity, postLogoutRedirectUri = "com.acme.app:/callback")
```

The tokens are forgotten, the refresh token is revoked, and the 9in session is ended in the
browser, so the next sign-in asks for credentials again. `postLogoutRedirectUri` must be one of the
application's **Allowed logout URLs**; without it, 9in shows a "You're signed out" page that the
user closes. `nine.signOut()` without an activity signs out of your app only: the 9in session in
the browser stays, and the next sign-in is instant (single sign-on).

## App Links

To use an https redirect URI, verify your domain for
[App Links](https://developer.android.com/training/app-links) and route the URL to the SDK's
redirect activity in your app's `AndroidManifest.xml` (with
`xmlns:tools="http://schemas.android.com/tools"` on its `<manifest>` element):

```xml
<activity
    android:name="io.ninein.android.NineRedirectActivity"
    android:exported="true"
    tools:node="merge">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="app.acme.com" android:path="/callback" />
    </intent-filter>
</activity>
```

`nineRedirectScheme` must still be set (to your application ID, for example).

## Where tokens are kept

`KeystoreCredentialStore`, the default, encrypts each value with AES-256-GCM under a key that is
created in the Android Keystore and never leaves it (hardware-backed on devices that have it). The
files are in the app's no-backup directory, so they are not copied to cloud backups or new devices.
A value that can't be decrypted reads as absent: the user signs in again.

To keep them elsewhere, implement `CredentialStore` (two methods, `read` and `write`) and pass it
with your configuration:

```kotlin
val nine = NineClient(NineConfig(issuer, clientId, redirectUri), myStore)
```

## Test your app

`signIn`, `signUp` and `signOut` also take a `BrowserStep`: a function that opens a URL and returns
the redirect. Tests can use it to sign in without a browser, for example against a fake server or
a 9in sandbox environment:

```kotlin
val nine = NineClient(NineConfig(issuer, clientId, redirectUri), MemoryCredentialStore())
val user = nine.signIn(BrowserStep { url, redirectUri ->
    signInOnTheHostedPage(url, redirectUri)   // returns "com.acme.app:/callback?code=…&state=…&iss=…"
})
```

An `io.ninein.http.HttpTransport` (from the Java SDK) replaces the HTTP client, for example to
use OkHttp or to record requests: `NineClient(config, store, transport)`.

## Issuers must use https

`NineClient` refuses an issuer that is not `https://` (`insecure_issuer`), so a typo can't send
tokens in clear text. Plain http is accepted for `localhost`, `*.localhost` and loopback addresses;
for other development hosts pass `NineConfig(…, allowInsecureIssuer = true)`. Endpoints from
discovery follow the same rule, and the discovery document must be for the issuer you configured.

## ID token signatures

The Java SDK checks the ID token's signature against your tenant's keys with the algorithms
Android provides: RS256/384/512, PS256/384/512, ES256 and ES384 on every supported version. EdDSA
(Ed25519) needs a recent Android release; on a version without it, an EdDSA-signed ID token is
accepted with the claim checks alone (issuer, audience, expiry, nonce). That is allowed for a
public client, which gets the ID token straight from 9in's token endpoint over TLS (OpenID Connect
Core 3.1.3.7). Tenants whose default key is RS256 (the default) or any RSA or EC key are verified
everywhere.

## Errors

Every failure is a `NineException` (`io.ninein.android.NineException`, a subclass of the Java
SDK's `io.ninein.NineException`) with a `code`, a `description`, and for HTTP errors a `status`:

| Code | Meaning |
|---|---|
| `canceled` | The user closed the browser |
| `login_required` | Nobody is signed in, or the session ended: sign in again |
| `access_denied`, `invalid_scope`, `invalid_target`, … | 9in refused the authorization request |
| `invalid_grant` | 9in refused the code or refresh token |
| `invalid_state`, `invalid_issuer`, `missing_code` | The redirect doesn't belong to the sign-in in progress |
| `invalid_id_token` | The ID token failed a check |
| `insecure_issuer`, `invalid_options` | A configuration mistake |
| `network_error`, `discovery_failed`, `jwks_unavailable`, `request_failed`, `invalid_json` | 9in couldn't be reached, or answered unexpectedly |
| `browser_not_found`, `storage_error` | No browser is installed, or the Keystore failed |

## Development

```bash
./gradlew :nine:testDebugUnitTest        # JVM and Robolectric tests (JDK 21 runs Robolectric on API 37)
./gradlew :nine:connectedDebugAndroidTest # on a device or emulator: Keystore, platform crypto
./gradlew :examples:app:assembleDebug     # the example app (examples/app)
./gradlew :nine:lintRelease
```

To change the Java core at the same time, build against a checkout of it:
`./gradlew --include-build ../java-sdk :nine:testDebugUnitTest`.

The live end-to-end tests sign in through 9in's real hosted pages and need the test tenant's
settings:

```bash
NINE_E2E=1 NINE_E2E_ENV=/path/to/.env.e2e ./gradlew :nine:testDebugUnitTest --tests '*LiveTest*'
```

The example app in `examples/app` is a Compose app with sign-in, sign-up, userinfo, refresh and
sign-out. Point it at your tenant with `-PnineIssuer=https://acme.9in.io -PnineClientId=app_…` and
register `io.ninein.example:/callback` as a callback and logout URL.

Report bugs in [issues](https://github.com/9in-io/android/issues).

## License

The MIT License (MIT). See [LICENSE](LICENSE). 9in is by [Cubelet Ltd](https://cubelet.co.uk).
