# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# Copyright 2026 Smart Outsourcing Business Consulting
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

"""OpenID Connect authorization start and callback correlation."""

import json
from urllib.parse import parse_qs, urlsplit

from werkzeug.urls import url_decode, url_encode

from odoo import SUPERUSER_ID, api, http
from odoo import registry as registry_get
from odoo.http import request

from odoo.addons.auth_oauth.controllers.main import (
    OAuthController,
    OAuthLogin,
    fragment_to_query_string,
)
from odoo.addons.web.controllers.utils import ensure_db


class OpenIDLogin(OAuthLogin):
    """Build one authorization-code URL per OIDC browser login attempt."""

    def list_providers(self):
        """Add opaque state, nonce, and S256 PKCE parameters to OIDC links."""
        providers = super().list_providers()
        for provider in providers:
            if provider.get("flow") != "id_token_code":
                continue
            params = url_decode(provider["auth_link"].split("?", 1)[-1])
            callback_uri = self._callback_uri()
            native_state = self.get_state(provider)
            native_state["d"] = request.session.db
            native_state["p"] = provider["id"]
            attempt, state = request.env[
                "auth.oidc.login.attempt"
            ].create_for_authorization(
                request.env["auth.oauth.provider"].sudo().browse(provider["id"]),
                request.session.db,
                request.session.sid,
                native_state,
                self._website_id(),
                callback_uri,
            )
            for key, value in {
                "response_type": "code",
                "redirect_uri": callback_uri,
                "state": state,
                "nonce": attempt.nonce,
                "code_challenge": attempt.code_challenge(),
                "code_challenge_method": "S256",
            }.items():
                params[key] = value
            if provider.get("scope"):
                params["scope"] = provider["scope"]
            provider["auth_link"] = "{}?{}".format(
                provider["auth_endpoint"], url_encode(params)
            )
        return providers

    @staticmethod
    def _callback_uri():
        """Return the one normalized OIDC callback URI for this request."""
        return f"{request.httprequest.url_root.rstrip('/')}/auth_oauth/signin"

    @staticmethod
    def _website_id():
        """Return the initiating website identifier when website is installed."""
        website = getattr(request, "website", None)
        return website.id if website else False


class OpenIDController(OAuthController):
    """Correlate opaque OIDC callback state before native terminal sign-in."""

    @http.route()
    @fragment_to_query_string
    def signin(self, **kw):
        """Claim OIDC state once, then restore trusted native state data."""
        state = kw.get("state")
        if self._is_non_oidc_native_state(state):
            return super().signin(**kw)
        attempt = self._claim_oidc_attempt(state)
        if not attempt:
            return self._generic_failure()
        kw["state"] = json.dumps(attempt.native_state)
        kw["_auth_oidc_attempt_id"] = attempt.id
        response = super().signin(**kw)
        if self._is_native_failure_redirect(response):
            return self._generic_failure()
        return response

    @staticmethod
    def _is_native_failure_redirect(response):
        """Return whether native OAuth converted this callback to a login error."""
        location = getattr(response, "location", None)
        if not location:
            return False
        parsed = urlsplit(location)
        return parsed.path == "/web/login" and "oauth_error" in parse_qs(
            parsed.query, keep_blank_values=True
        )

    @staticmethod
    def _is_non_oidc_native_state(state):
        """Return whether a native-shaped state resolves to a non-OIDC provider."""
        if not isinstance(state, str):
            return False
        try:
            value = json.loads(state)
        except (TypeError, ValueError):
            return False
        if not isinstance(value, dict):
            return False
        database_name = value.get("d")
        provider_id = value.get("p")
        if (
            not isinstance(database_name, str)
            or not isinstance(provider_id, int)
            or not http.db_filter([database_name])
        ):
            return False
        registry = registry_get(database_name)
        with registry.cursor() as cursor:
            env = api.Environment(cursor, SUPERUSER_ID, {})
            provider = env["auth.oauth.provider"].browse(provider_id).exists()
            return bool(provider and provider.flow not in ("id_token", "id_token_code"))

    @staticmethod
    def _claim_oidc_attempt(state):
        """Claim state only in the database already bound to this session."""
        database_name = request.session.db
        if not database_name or not http.db_filter([database_name]):
            return False
        ensure_db(db=database_name)
        return request.env["auth.oidc.login.attempt"].claim_from_callback(
            state, database_name, request.session.sid
        )

    @staticmethod
    def _generic_failure():
        """Return the fixed local failure path without provider information."""
        request.session["auth_oidc_error"] = True
        response = request.redirect("/web/login", 303)
        response.autocorrect_location_header = False
        return response
