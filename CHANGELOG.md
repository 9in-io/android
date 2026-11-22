# Changelog

## 0.1.0

First release of the official Android SDK for 9in (`com.github.9in-io:android`, package
`io.ninein.android`), for Android 8.0 (API 26) and later. Built on the 9in Java SDK
(`com.github.9in-io:java` 0.1.0), whose `AuthClient` does the protocol.

- `NineClient`: sign-in with the authorization code flow and PKCE (S256) in Custom Tabs (or the
  browser), with endpoints from OpenID Connect discovery. Checks `state` (single use, constant
  time; a redirect for another sign-in is refused before anything in it counts), the RFC 9207
  `iss` parameter and the `nonce`.
- ID tokens verified by the Java core against the tenant's JWKS: RS256/384/512, PS256/384/512,
  ES256, ES384, and EdDSA where Android has Ed25519 (elsewhere an EdDSA ID token passes with the
  claim checks, as OpenID Connect allows for a public client). Issuer, audience, `azp`, expiry and
  subject are checked, with a 5-minute tolerance for device clocks.
- `signIn`, `signUp` (`prompt=create`), `accessToken()` (refresh with rotation, one refresh for
  concurrent callers), `refresh()`, `userInfo()`, `credentials()`, and `signOut` (revokes the
  refresh token and ends the 9in session in the browser).
- `state: StateFlow<AuthState>` (`Loading`, `SignedOut`, `SignedIn(user)`), `user`, `isSignedIn`.
- `KeystoreCredentialStore`: tokens encrypted with AES-256-GCM under an Android Keystore key, in
  the no-backup directory. Pluggable `CredentialStore`, `MemoryCredentialStore` for tests.
- `NineRedirectActivity` with the `nineRedirectScheme` manifest placeholder, and App Links.
- Sign-ins survive activity recreation and process death while the browser is open.
- `BrowserStep` and `HttpTransport` interfaces, so tests can run the flow without a UI.
- Issuers must be https (`insecure_issuer`), with `allowInsecureIssuer` for development hosts.
- Errors are `NineException` (a subclass of the Java SDK's) with a `code`, `description` and HTTP
  `status`. `HttpTransport` is the Java SDK's `io.ninein.http.HttpTransport`.
