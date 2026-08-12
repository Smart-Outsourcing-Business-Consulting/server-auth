## Setup for Microsoft Entra ID

1. In Microsoft Entra admin center, open **Entra ID** > **App registrations** >
   the Odoo app > **Overview**. Copy **Application (client) ID** and
   **Directory (tenant) ID**.
2. Open **Certificates & secrets** > **Client secrets**, create a secret, copy
   its **Value** immediately, and record its expiry. Enter the Value, not the
   Secret ID, in Odoo's **Client Secret** field.
3. On **Authentication**, register
   `https://<public-odoo-host>/auth_oauth/signin` as a Web redirect URI for
   each supported public Odoo host. Do not use wildcard URIs or the old
   miniOrange callback.
4. Open **Endpoints** and select **OpenID Connect metadata document**, or open
   `https://login.microsoftonline.com/<DIRECTORY-TENANT-ID>/v2.0/.well-known/openid-configuration`.
   Copy its JSON values without hand-editing endpoint strings.

   | Metadata key | Odoo field |
   | --- | --- |
   | `authorization_endpoint` | **Authorization URL** |
   | `token_endpoint` | **Token URL** |
   | `issuer` | **Issuer** |
   | `jwks_uri` | **JWKS URL** |

5. In Odoo, activate developer mode, then open **Settings** > **Users &
   Companies** > **OAuth Providers** > **New**. Set **Provider name**, **Auth
   Flow** to **OpenID Connect (authorization code flow)**, **Client ID**,
   **Client Secret**, **Login button label**, **Authorization URL**, **Scope**,
   **Token URL**, **JWKS URL**, **Issuer**, **Tenant ID**, **Allowed
   Algorithms**, and **Clock Skew Seconds**. Set **Scope** to
   `openid profile email`, set **Allowed Algorithms** to **RS256**, and set
   **Clock Skew Seconds** from 0 through 300 seconds. `openid` is required by
   the adapter; `profile` and `email` request optional name and email claims.
   An email claim is not guaranteed. **UserInfo URL** is optional and can
   remain empty. Leave **Allowed** off until the values are reviewed, then
   enable the provider.

Use the tenant-specific v2 authority for this single-tenant workforce
application. Do not configure v1 endpoints, `consumers`, `common`, or
`organizations`. The `jwks_uri` value identifies the HTTPS JSON set of
Microsoft public signing keys. The `issuer` value is the exact issuer URL from
metadata that the ID token `iss` claim must match.

Microsoft references: [OIDC and
metadata](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc),
[access tokens and signing
keys](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens),
[application
registration](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app),
[redirect
URIs](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri),
[authorization code
flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow),
[tenant
IDs](https://learn.microsoft.com/en-us/entra/fundamentals/how-to-find-tenant),
and [application
credentials](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials).

## Optional Keycloak setup

Keycloak is an optional standards-compliant provider for this adapter. The
Microsoft Entra lifecycle addon does not install, contact, or depend on
Keycloak.

In Keycloak:

1. Configure a new client.
2. Enable Authorization Code Flow.
3. Configure a confidential client and note its client secret.
4. Register the exact redirect URL
   `https://<server>/auth_oauth/signin` for every supported Odoo host.

In Odoo, create an OAuth Provider with these settings:

- Provider name: Keycloak
- Auth Flow: OpenID Connect (authorization code flow)
- Client ID: the client ID configured in Keycloak
- Client Secret: the secret from the Keycloak Credentials tab
- Allowed: yes
- Body: the link text to appear on the login page, such as Login with Keycloak
- Scope: openid email
- Authentication URL: the `authorization_endpoint` URL from the realm's
  OpenID Endpoint Configuration
- Token URL: the `token_endpoint` URL from the realm's OpenID Endpoint
  Configuration
- JWKS URL: the `jwks_uri` URL from the realm's OpenID Endpoint Configuration
- Issuer: the exact issuer from the OpenID Endpoint Configuration
- Allowed Algorithms: the asymmetric signing algorithm used by the realm
