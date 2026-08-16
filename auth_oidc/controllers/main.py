# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# Copyright 2026 Smart Outsourcing Business Consulting
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

"""OpenID Connect authorization start and callback correlation."""

import json
import secrets
from urllib.parse import parse_qs, urlsplit

from werkzeug.urls import url_encode

from odoo import SUPERUSER_ID, api, http
from odoo import registry as registry_get
from odoo.exceptions import AccessDenied
from odoo.http import request

from odoo.addons.auth_oauth.controllers.main import (
    OAuthController,
    OAuthLogin,
    fragment_to_query_string,
)
from odoo.addons.web.controllers.utils import ensure_db

START_STATE_SESSION_KEY = "auth_oidc_start_states"
MAX_STAGED_START_INTENTS = 16


class OpenIDLogin(OAuthLogin):
    """Stage native state and render one local start link per OIDC provider."""

    def list_providers(self):
        """Render OIDC links without creating persistent attempt records."""
        providers = super().list_providers()
        previous_states = dict(request.session.get(START_STATE_SESSION_KEY) or {})
        new_states = {}
        for provider in providers:
            if provider.get("flow") != "id_token_code":
                continue
            native_state = self.get_state(provider)
            native_state["d"] = request.session.db
            native_state["p"] = provider["id"]
            intent = secrets.token_urlsafe(32)
            while intent in previous_states or intent in new_states:
                intent = secrets.token_urlsafe(32)
            new_states[intent] = {
                "native_state": native_state,
                "website_id": self._website_id(),
                "callback_uri": self._callback_uri(),
            }
            provider["auth_link"] = "/auth_oidc/start?{}".format(
                url_encode({"intent": intent})
            )
        retained_count = max(MAX_STAGED_START_INTENTS - len(new_states), 0)
        start_states = (
            dict(list(previous_states.items())[-retained_count:])
            if retained_count
            else {}
        )
        start_states.update(new_states)
        request.session[START_STATE_SESSION_KEY] = start_states
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

    @http.route("/auth_oidc/start", type="http", auth="none", readonly=False)
    def start(self, intent=None, **_kw):
        """Create one bounded attempt after a staged provider link is followed."""
        ensure_db()
        start_data = self._pop_start_state(intent)
        if not isinstance(start_data, dict):
            return self._generic_failure()
        native_state = start_data.get("native_state")
        if not isinstance(native_state, dict):
            return self._generic_failure()
        provider_id = native_state.get("p")
        callback_uri = start_data.get("callback_uri")
        website_id = start_data.get("website_id") or False
        if (
            type(provider_id) is not int
            or provider_id <= 0
            or native_state.get("d") != request.session.db
            or not isinstance(callback_uri, str)
            or not callback_uri
            or (website_id is not False and type(website_id) is not int)
        ):
            return self._generic_failure()

        provider_record = (
            request.env["auth.oauth.provider"]
            .sudo()
            .search(
                [
                    ("id", "=", provider_id),
                    ("enabled", "=", True),
                    ("flow", "=", "id_token_code"),
                ],
                limit=1,
            )
        )
        if not provider_record:
            return self._generic_failure()

        try:
            attempt, state = request.env[
                "auth.oidc.login.attempt"
            ]._create_for_authorization(
                provider_record,
                request.session.db,
                request.session.sid,
                native_state,
                website_id,
                callback_uri,
            )
        except AccessDenied:
            return self._generic_failure()

        params = {
            "response_type": "code",
            "client_id": provider_record.client_id,
            "redirect_uri": callback_uri,
            "state": state,
            "nonce": attempt.nonce,
            "code_challenge": attempt.code_challenge(),
            "code_challenge_method": "S256",
        }
        if provider_record.scope:
            params["scope"] = provider_record.scope
        response = request.redirect(
            f"{provider_record.auth_endpoint}?{url_encode(params)}",
            303,
            local=False,
        )
        response.autocorrect_location_header = False
        return response

    @staticmethod
    def _pop_start_state(intent):
        """Consume one opaque session-staged native OAuth state."""
        if not isinstance(intent, str):
            return None
        start_states = dict(request.session.get(START_STATE_SESSION_KEY) or {})
        start_data = start_states.pop(intent, None)
        if start_states:
            request.session[START_STATE_SESSION_KEY] = start_states
        else:
            request.session.pop(START_STATE_SESSION_KEY, None)
        return start_data

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
