This module adds a strict OpenID Connect authorization-code adapter to Odoo.
Each login uses server-side state, nonce, and PKCE material; the adapter then
validates the token signature and required claims before it hands an immutable
principal to Odoo's native OAuth sign-in flow.

Implicit and hybrid browser-token flows are not supported. This addon does not
choose user types, groups, companies, or employee records; a downstream policy
addon owns those decisions.
