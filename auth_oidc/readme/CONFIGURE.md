## Setup for Microsoft Azure

Example configuration with the required OpenID Connect authorization-code
flow.

1. configure a new web application in Azure with OpenID and code flow (see
the [provider
documentation](https://docs.microsoft.com/en-us/powerapps/maker/portals/configure/configure-openid-provider)))

2. Register the exact callback URI for every supported Odoo host:
   `https://<server>/auth_oauth/signin`. Wildcards are not supported. The
   callback URI used for a login is derived from the proxy-adjusted Odoo
   request origin, so verify proxy configuration and every registered branch
   host before deployment.

3. Create a new authentication provider in Odoo with the authorization-code
   flow, `openid` scope, exact issuer, token URL, JWKS URL, and an asymmetric
   allowed algorithm (RS256 for Microsoft Entra). Set the Entra tenant ID when
   the provider is tenant-restricted.

![image](../static/description/oauth-microsoft_azure-api_permissions.png)

![image](../static/description/oauth-microsoft_azure-optional_claims.png)

Single tenant provider limits the access to user of your tenant, while
Multitenants allow access for all AzureAD users, so user of foreign
companies can use their AzureAD login without an guest account.

- Provider Name: Azure AD Single Tenant
- Client ID: Application (client) id
- Client Secret: Client secret
- Allowed: yes

or

- Provider Name: Azure AD Multitenant
- Client ID: Application (client) id
- Client Secret: Client secret
- Allowed: yes
- replace {tenant_id} in urls with your Azure tenant id

![image](../static/description/odoo-azure_ad_multitenant.png)

## Setup for Keycloak

Example configuration with the required OpenID Connect authorization-code
flow.

In Keycloak:

1. configure a new Client
2. make sure Authorization Code Flow is
Enabled.
3. configure the client Access Type as "confidential" and take
note of the client secret in the Credentials tab
4. register the exact redirect URL
`https://<server>/auth_oauth/signin` for every supported Odoo host

In Odoo, create a new Oauth Provider with the following parameters:

- Provider name: Keycloak (or any name you like that identify your
  keycloak provider)
- Auth Flow: OpenID Connect (authorization code flow)
- Client ID: the same Client ID you entered when configuring the client
  in Keycloak
- Client Secret: found in keycloak on the client Credentials tab
- Allowed: yes
- Body: the link text to appear on the login page, such as Login with
  Keycloak
- Scope: openid email
- Authentication URL: The "authorization_endpoint" URL found in the
  OpenID Endpoint Configuration of your Keycloak realm
- Token URL: The "token_endpoint" URL found in the OpenID Endpoint
  Configuration of your Keycloak realm
- JWKS URL: The "jwks_uri" URL found in the OpenID Endpoint
  Configuration of your Keycloak realm
- Issuer: the exact issuer from the OpenID Endpoint Configuration
- Allowed Algorithms: the asymmetric signing algorithm used by the realm
