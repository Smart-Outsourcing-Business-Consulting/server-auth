On the login page, click the authentication provider you configured. The
provider must use the authorization-code flow.

The adapter creates a server-side attempt for the current browser session,
provider, and database. It sends opaque state, a nonce, and an S256 PKCE
challenge. The attempt expires after 10 minutes and can be claimed only once;
the nonce and PKCE verifier are not placed in browser-visible state.

On callback, the adapter exchanges the code with the stored verifier and
validates the token algorithm, signature, times, audience, authorized party
when required, exact issuer, nonce, optional tenant ID, and non-empty subject.
Only immutable validated claims reach the extension hook.

If correlation, exchange, validation, or handoff fails, the callback records a
fixed terminal reason and redirects locally to `/web/login`. It does not place
the authorization code, tokens, claims, or provider response in the redirect.
A new browser login attempt is required after failure.

The default hook may use native account lookup. A downstream lifecycle policy
may perform account lookup and provisioning before it invokes the native
terminal path. Native Odoo retains credential authentication, session rotation,
and the final local redirect.
