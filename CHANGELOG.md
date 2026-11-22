# Changelog

## 0.1.0

First release of the official Android SDK for 9in (`com.github.9in-io:android`, package
`io.ninein.android`), for Android 6.0 (API 23) and later.

- `NineClient`: sign-in with the authorization code flow and PKCE (S256) in Custom Tabs (or the
  browser), with endpoints from OpenID Connect discovery. Checks `state` (single use, constant
  time), the RFC 9207 `iss` parameter (required when the server advertises it) and the `nonce`.
- ID tokens verified against the tenant's JWKS: RS256/384/512, PS256/384/512, ES256, ES384 and
  EdDSA (Ed25519, with a built-in verifier for Android versions that lack one). The key decides the
  algorithm; issuer, audience, `azp`, expiry, `nbf` and subject are checked. JWKS cached for 10
  minutes, refetched once for an unknown `kid`, unknown kids throttled for 60 seconds.
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
- Errors are `NineException` with a `code`, `description` and HTTP `status`.
