This module adds a strict OpenID Connect authorization-code adapter to Odoo.
Each login uses server-side state, nonce, and PKCE material. The adapter
validates the signed ID token and its required claims before it hands an
immutable principal to native Odoo authentication or a typed downstream hook.

Implicit and hybrid browser-token flows are not supported. This addon does not
choose user types, groups, companies, or employee records. Those decisions
belong to the downstream policy addon and are documented in the pinned
[Microsoft Entra ID lifecycle guide](https://github.com/Smart-Outsourcing-Business-Consulting/miniorange_oauth_20/blob/57cbba126453e8ab6b4690da9678ec75571ecfb4/docs/entra_sso_administrator_guide.md).
