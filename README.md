# app-auth-client

Alpha 0.1.0-alpha.5; Apache-2.0. Not for production use.

`@categori/app-auth-client` supplies `createAuthClient` for browser authorization-code/PKCE, session loading, sign-in, sign-out and optional renewable access-token sessions. Applications configure provider endpoints, public client IDs, scopes, callback policy and separate storage namespaces. Login markup, colors and logos stay application-owned.

The client guards delayed callback and refresh responses against newer sign-in, sign-out, storage and navigation state. Registration, password reset and logout endpoints are optional provider capabilities. Access-token renewal is opt-in; a display-only memory session cannot authorize API requests.

ID-token fields are decoded for display and are not cryptographically verified here. APIs must validate tokens and current identity/resource authorization independently. Browser storage checks are not cross-tab transactions. Sharing code does not share tokens, join users or establish a cross-application identity registry. There is no provider discovery, global logout or client secret in this package. Node 24+ runs the synthetic, offline unit tests.

Registry packages are not published by this source release. Node manifests retain `private: true` to guard against accidental npm publication. See the repository CI for offline test commands.
