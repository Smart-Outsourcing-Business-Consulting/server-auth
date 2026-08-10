## Setup for Microsoft Entra ID

Create a web application in Microsoft Entra ID with OpenID Connect
authorization-code flow enabled.

1. Register the exact callback URI for every supported Odoo host:
   `https://<server>/auth_oauth/signin`. Wildcards are not supported. The
   callback URI used for a login is derived from the proxy-adjusted Odoo
   request origin, so verify proxy configuration and every registered branch
   host before deployment.

2. Create a new authentication provider in Odoo with the authorization-code
   flow, `openid` scope, exact issuer, token URL, JWKS URL, and an asymmetric
   allowed algorithm (RS256 for Microsoft Entra). Set the exact Entra tenant ID
   when the provider is tenant-restricted.

3. Enter the application client ID and, for a confidential client, its client
   secret. Enable the provider only after every trust value has been reviewed.

![image](../static/description/oauth-microsoft_azure-api_permissions.png)

![image](../static/description/oauth-microsoft_azure-optional_claims.png)

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
