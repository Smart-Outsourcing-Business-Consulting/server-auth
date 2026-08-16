# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import base64
import contextlib
import hashlib
import json
import logging
import re
import time
from dataclasses import FrozenInstanceError
from datetime import timedelta
from unittest.mock import patch
from urllib.parse import parse_qs, unquote_plus, urlencode, urlparse, urlunparse

import responses
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt
from jose.utils import long_to_base64

import odoo
from odoo.exceptions import AccessDenied, ValidationError
from odoo.tests import common

from odoo.addons.auth_oauth.controllers.main import OAuthController
from odoo.addons.website.tools import MockRequest as _MockRequest

from ..controllers.main import (
    MAX_STAGED_START_INTENTS,
    START_STATE_SESSION_KEY,
    OpenIDController,
    OpenIDLogin,
)
from ..models.auth_oauth_provider import OIDCAuthenticationError
from ..models.res_users import OIDCFailure, ResUsers, VerifiedOIDCLoginContext

BASE_URL = f"http://localhost:{odoo.tools.config['http_port']}"


def _redirect_honoring_local(env):
    """Return one ``request.redirect`` stand-in that honors ``local``.

    The website ``MockRequest`` fixture wires ``redirect`` straight to
    ``IrHttp._redirect``, which has no ``local`` parameter at all, so it
    silently drops the scheme/host-stripping ``odoo.http.Request.redirect``
    normally applies. Reproduce that stripping here so a mocked request
    exercises the same host-handling a real routed request would.
    """

    def _redirect(location, code=303, local=True):
        if local:
            parsed = urlparse(location)
            location = urlunparse(("", "", parsed.path, parsed.params, parsed.query, parsed.fragment))
            if not location.startswith("/"):
                location = "/" + location
        return env["ir.http"]._redirect(location, code)

    return _redirect


@contextlib.contextmanager
def MockRequest(env):
    with _MockRequest(env) as request:
        request.httprequest.url_root = BASE_URL + "/"
        request.params = {}
        request.session.db = env.cr.dbname
        request.session.sid = "auth-oidc-test-session"
        request.redirect = _redirect_honoring_local(env)
        yield request


class TestAuthOIDCAuthorizationCodeFlow(common.HttpCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        (
            cls.rsa_key_pem,
            cls.rsa_key_public_pem,
            cls.rsa_key_public_jwk,
        ) = cls._generate_key()
        (
            cls.second_key_pem,
            cls.second_key_public_pem,
            cls.second_key_public_jwk,
        ) = cls._generate_key()

    @staticmethod
    def _generate_key():
        rsa_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        rsa_key_pem = rsa_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode("utf8")
        rsa_key_public = rsa_key.public_key()
        rsa_key_public_pem = rsa_key_public.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf8")
        jwk = {
            # https://datatracker.ietf.org/doc/html/rfc7518#section-6.1
            "kty": "RSA",
            "use": "sig",
            "n": long_to_base64(rsa_key_public.public_numbers().n).decode("utf-8"),
            "e": long_to_base64(rsa_key_public.public_numbers().e).decode("utf-8"),
        }
        return rsa_key_pem, rsa_key_public_pem, jwk

    def setUp(self):
        super().setUp()
        # search our test provider and bind the demo user to it
        self.provider_rec = self.env["auth.oauth.provider"].search(
            [("client_id", "=", "auth_oidc-test")]
        )
        self.assertEqual(len(self.provider_rec), 1)

    def _auth_oauth_denied(self, provider_id, params):
        """Run one terminal OIDC failure without the test rollback savepoint."""
        try:
            self.env["res.users"].auth_oauth(provider_id, params)
        except AccessDenied:
            return
        self.fail("AccessDenied not raised")

    @staticmethod
    def _signin_controller_boundary(**params):
        """Call the controller endpoint without the unrouted HTTP wrapper."""
        return OpenIDController.signin.original_endpoint(OpenIDController(), **params)

    @staticmethod
    def _start_controller_boundary(**params):
        """Call the OIDC initiation endpoint without the routed HTTP wrapper."""
        return OpenIDController.start.original_endpoint(OpenIDController(), **params)

    def test_login_render_stages_local_start_without_attempt(self):
        """Test rendering creates no attempt or secret-bearing local query."""
        # disable existing providers except our test provider
        self.env["auth.oauth.provider"].search(
            [("client_id", "!=", "auth_oidc-test")]
        ).write(dict(enabled=False))
        attempt_model = self.env["auth.oidc.login.attempt"]
        with MockRequest(self.env) as mock_request:
            mock_request.params = {
                "redirect": "/web#home",
                "token": "invitation-token-sentinel",
            }
            providers = OpenIDLogin().list_providers()
            self.assertEqual(len(providers), 1)
            auth_link = providers[0]["auth_link"]
        parsed = urlparse(auth_link)
        self.assertEqual(parsed.path, "/auth_oidc/start")
        start_query = parse_qs(parsed.query)
        self.assertEqual(set(start_query), {"intent"})
        self.assertGreaterEqual(len(start_query["intent"][0]), 32)
        self.assertNotIn("invitation-token-sentinel", auth_link)
        self.assertEqual(attempt_model.search_count([]), 0)

    def test_login_render_bounds_staged_start_intents(self):
        """Test repeated anonymous rendering cannot grow session intent state."""
        self.env["auth.oauth.provider"].search(
            [("client_id", "!=", "auth_oidc-test")]
        ).write({"enabled": False})
        with MockRequest(self.env) as mock_request:
            for index in range(MAX_STAGED_START_INTENTS + 5):
                mock_request.params = {"redirect": f"/web#{index}"}
                OpenIDLogin().list_providers()
            self.assertEqual(
                len(mock_request.session[START_STATE_SESSION_KEY]),
                MAX_STAGED_START_INTENTS,
            )
        self.assertFalse(self.env["auth.oidc.login.attempt"].search([]))

    def test_start_creates_attempt_and_redirects_to_provider(self):
        """Test a staged click creates one complete authorization attempt."""
        self.env["auth.oauth.provider"].search(
            [("client_id", "!=", "auth_oidc-test")]
        ).write({"enabled": False})
        with MockRequest(self.env) as mock_request:
            mock_request.params = {
                "redirect": "/web#home",
                "token": "invitation-token-sentinel",
            }
            auth_link = OpenIDLogin().list_providers()[0]["auth_link"]
            start_query = parse_qs(urlparse(auth_link).query)
            response = self._start_controller_boundary(intent=start_query["intent"][0])
            replay_response = self._start_controller_boundary(
                intent=start_query["intent"][0]
            )

        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.location.startswith(self.provider_rec.auth_endpoint))
        self.assertEqual(replay_response.status_code, 303)
        self.assertEqual(replay_response.location, "/web/login")
        params = parse_qs(urlparse(response.location).query)
        self.assertEqual(params["client_id"], [self.provider_rec.client_id])
        state = params["state"][0]
        attempt = self.env["auth.oidc.login.attempt"].search(
            [("state_digest", "=", hashlib.sha256(state.encode()).hexdigest())]
        )
        self.assertEqual(attempt.provider_id, self.provider_rec)
        self.assertEqual(attempt.database_name, self.env.cr.dbname)
        self.assertEqual(attempt.status, "pending")
        self.assertEqual(
            unquote_plus(attempt.native_state["r"]), BASE_URL + "/web#home"
        )
        self.assertEqual(attempt.native_state["t"], "invitation-token-sentinel")
        self.assertEqual(attempt.callback_uri, BASE_URL + "/auth_oauth/signin")
        self.assertEqual(
            {
                key: params[key]
                for key in {
                    "response_type",
                    "redirect_uri",
                    "state",
                    "nonce",
                    "code_challenge",
                    "code_challenge_method",
                    "scope",
                }
            },
            {
                "response_type": ["code"],
                "redirect_uri": [BASE_URL + "/auth_oauth/signin"],
                "state": [state],
                "nonce": [attempt.nonce],
                "code_challenge": [attempt.code_challenge()],
                "code_challenge_method": ["S256"],
                "scope": ["openid email"],
            },
        )

    def test_repeated_start_supersedes_same_session_pending_attempt(self):
        """Test one session/provider/website retains only its latest attempt."""
        self.env["auth.oauth.provider"].search(
            [("client_id", "!=", "auth_oidc-test")]
        ).write({"enabled": False})
        with MockRequest(self.env) as mock_request:
            mock_request.params = {"redirect": "/web#first"}
            first_link = OpenIDLogin().list_providers()[0]["auth_link"]
            first_intent = parse_qs(urlparse(first_link).query)["intent"][0]
            mock_request.params = {"redirect": "/web#second"}
            second_link = OpenIDLogin().list_providers()[0]["auth_link"]
            second_intent = parse_qs(urlparse(second_link).query)["intent"][0]
            first_response = self._start_controller_boundary(intent=first_intent)
            first_attempt = self.env["auth.oidc.login.attempt"].search(
                [("provider_id", "=", self.provider_rec.id)]
            )
            self.assertEqual(
                unquote_plus(first_attempt.native_state["r"]), BASE_URL + "/web#first"
            )
            second_response = self._start_controller_boundary(intent=second_intent)

        first_state = parse_qs(urlparse(first_response.location).query)["state"][0]
        second_state = parse_qs(urlparse(second_response.location).query)["state"][0]
        self.assertNotEqual(first_state, second_state)
        attempts = self.env["auth.oidc.login.attempt"].search(
            [("provider_id", "=", self.provider_rec.id)]
        )
        self.assertEqual(len(attempts), 1)
        self.assertEqual(
            attempts.state_digest, hashlib.sha256(second_state.encode()).hexdigest()
        )
        self.assertEqual(
            unquote_plus(attempts.native_state["r"]), BASE_URL + "/web#second"
        )
        self.assertFalse(
            self.env["auth.oidc.login.attempt"].claim_from_callback(
                first_state, self.env.cr.dbname, "auth-oidc-test-session"
            )
        )

    def test_start_without_staged_intent_fails_without_attempt(self):
        """Test direct initiation cannot mint an attempt for arbitrary input."""
        with MockRequest(self.env) as mock_request:
            response = self._start_controller_boundary(intent="not-staged")
            self.assertTrue(mock_request.session["auth_oidc_error"])
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.location, "/web/login")
        self.assertFalse(self.env["auth.oidc.login.attempt"].search([]))

    def test_start_rechecks_provider_after_intent_is_staged(self):
        """Test a disabled provider cannot use an already-rendered start link."""
        self.env["auth.oauth.provider"].search(
            [("client_id", "!=", "auth_oidc-test")]
        ).write({"enabled": False})
        with MockRequest(self.env) as mock_request:
            auth_link = OpenIDLogin().list_providers()[0]["auth_link"]
            intent = parse_qs(urlparse(auth_link).query)["intent"][0]
            self.provider_rec.enabled = False
            response = self._start_controller_boundary(intent=intent)
            self.assertTrue(mock_request.session["auth_oidc_error"])
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.location, "/web/login")
        self.assertFalse(self.env["auth.oidc.login.attempt"].search([]))

    def test_attempt_claim_is_session_bound_and_one_time(self):
        """Test that only the initiating session can atomically claim state."""
        attempt_model = self.env["auth.oidc.login.attempt"]
        attempt, state = attempt_model._create_for_authorization(
            self.provider_rec,
            self.env.cr.dbname,
            "initial-session",
            {"d": self.env.cr.dbname, "p": self.provider_rec.id, "r": "/odoo"},
            False,
            BASE_URL + "/auth_oauth/signin",
        )
        self.assertFalse(
            attempt_model.claim_from_callback(
                state, self.env.cr.dbname, "different-session"
            )
        )
        self.assertEqual(attempt.status, "pending")

        claimed = attempt_model.claim_from_callback(
            state, self.env.cr.dbname, "initial-session"
        )
        self.assertEqual(claimed, attempt)
        self.assertEqual(claimed.status, "claimed")
        self.assertFalse(
            attempt_model.claim_from_callback(
                state, self.env.cr.dbname, "initial-session"
            )
        )

    def test_pending_attempt_capacity_is_bounded_per_provider_and_website(self):
        """Test distinct sessions cannot grow one provider/site past its bound."""
        attempt_model = self.env["auth.oidc.login.attempt"]
        create_values = (
            self.provider_rec,
            self.env.cr.dbname,
        )
        with patch(
            "odoo.addons.auth_oidc.models.auth_oidc_login_attempt."
            "PENDING_ATTEMPT_LIMIT",
            2,
        ):
            for session_id in ("capacity-session-1", "capacity-session-2"):
                attempt_model._create_for_authorization(
                    *create_values,
                    session_id,
                    {"d": self.env.cr.dbname, "p": self.provider_rec.id},
                    False,
                    BASE_URL + "/auth_oauth/signin",
                )
            with self.assertRaises(AccessDenied):
                attempt_model._create_for_authorization(
                    *create_values,
                    "capacity-session-3",
                    {"d": self.env.cr.dbname, "p": self.provider_rec.id},
                    False,
                    BASE_URL + "/auth_oauth/signin",
                )
            website_attempt, _state = attempt_model._create_for_authorization(
                *create_values,
                "capacity-session-3",
                {"d": self.env.cr.dbname, "p": self.provider_rec.id},
                42,
                BASE_URL + "/auth_oauth/signin",
            )

        self.assertEqual(
            attempt_model.search_count(
                [
                    ("provider_id", "=", self.provider_rec.id),
                    ("website_id", "=", False),
                    ("status", "=", "pending"),
                ]
            ),
            2,
        )
        self.assertEqual(website_attempt.website_id, 42)

    def test_expired_pending_attempt_is_removed_before_capacity_check(self):
        """Test an expired row neither remains stored nor blocks fresh login."""
        attempt_model = self.env["auth.oidc.login.attempt"]
        with patch(
            "odoo.addons.auth_oidc.models.auth_oidc_login_attempt."
            "PENDING_ATTEMPT_LIMIT",
            1,
        ):
            expired, _state = attempt_model._create_for_authorization(
                self.provider_rec,
                self.env.cr.dbname,
                "expired-capacity-session",
                {"d": self.env.cr.dbname, "p": self.provider_rec.id},
                False,
                BASE_URL + "/auth_oauth/signin",
            )
            expired.expires_at = odoo.fields.Datetime.now() - timedelta(seconds=1)
            fresh, _state = attempt_model._create_for_authorization(
                self.provider_rec,
                self.env.cr.dbname,
                "fresh-capacity-session",
                {"d": self.env.cr.dbname, "p": self.provider_rec.id},
                False,
                BASE_URL + "/auth_oauth/signin",
            )

        self.assertFalse(expired.exists())
        self.assertTrue(fresh.exists())

    def test_cleanup_deletes_expired_pending_without_terminal_retention_delay(self):
        """Test pending expiry and terminal diagnostic retention stay distinct."""
        attempt_model = self.env["auth.oidc.login.attempt"]
        expired, _state = attempt_model._create_for_authorization(
            self.provider_rec,
            self.env.cr.dbname,
            "cron-expired-session",
            {"d": self.env.cr.dbname, "p": self.provider_rec.id},
            False,
            BASE_URL + "/auth_oauth/signin",
        )
        unexpired, _state = attempt_model._create_for_authorization(
            self.provider_rec,
            self.env.cr.dbname,
            "cron-unexpired-session",
            {"d": self.env.cr.dbname, "p": self.provider_rec.id},
            False,
            BASE_URL + "/auth_oauth/signin",
        )
        recent_terminal, _state = attempt_model._create_for_authorization(
            self.provider_rec,
            self.env.cr.dbname,
            "cron-terminal-session",
            {"d": self.env.cr.dbname, "p": self.provider_rec.id},
            False,
            BASE_URL + "/auth_oauth/signin",
        )
        expired.expires_at = odoo.fields.Datetime.now() - timedelta(seconds=1)
        recent_terminal.write(
            {
                "status": "failed",
                "terminal_at": odoo.fields.Datetime.now(),
            }
        )

        attempt_model._cron_cleanup_expired_attempts()

        self.assertFalse(expired.exists())
        self.assertTrue(unexpired.exists())
        self.assertTrue(recent_terminal.exists())

    def test_native_shaped_state_cannot_bypass_an_oidc_attempt(self):
        """Test that a native-shaped callback state cannot bypass OIDC correlation."""
        state = json.dumps({"d": self.env.cr.dbname, "p": self.provider_rec.id})
        with MockRequest(self.env) as mock_request:
            response = self._signin_controller_boundary(state=state)
            self.assertTrue(mock_request.session["auth_oidc_error"])
        self.assertEqual(response.location, "/web/login")
        self.assertNotIn("?", response.location)

    def test_non_ascii_state_fails_at_the_fixed_login_destination(self):
        """Test malformed callback state never raises or remains in the URL."""
        with MockRequest(self.env) as mock_request:
            response = self._signin_controller_boundary(state="not-ascii-€")
            self.assertTrue(mock_request.session["auth_oidc_error"])
        self.assertEqual(response.location, "/web/login")
        self.assertNotIn("?", response.location)

    def test_native_failure_redirect_detection_preserves_success_locations(self):
        """Test native error redirects alone are normalized after callback claim."""
        failure = type("Response", (), {"location": "/web/login?oauth_error=3"})()
        success = type("Response", (), {"location": "/odoo"})()
        self.assertTrue(OpenIDController._is_native_failure_redirect(failure))
        self.assertFalse(OpenIDController._is_native_failure_redirect(success))

    def test_claim_without_a_session_database_does_not_open_an_environment(self):
        """Test that callback correlation fails before accessing an environment."""

        class RequestWithoutDatabase:
            session = type("Session", (), {"db": False})()

            @property
            def env(self):
                raise AssertionError("callback must not access request.env")

        with patch(
            "odoo.addons.auth_oidc.controllers.main.request",
            RequestWithoutDatabase(),
        ):
            self.assertFalse(OpenIDController._claim_oidc_attempt("opaque-state"))

    def _prepare_login_test_user(self):
        """Bind the demo user to the provider-scoped standard subject."""
        user = self.env.ref("base.user_demo")
        user.write(
            {"oauth_provider_id": self.provider_rec.id, "oauth_uid": "test-subject"}
        )
        return user

    def _claimed_attempt(self):
        """Create and claim one attempt for direct token-boundary tests."""
        attempt, state = self.env["auth.oidc.login.attempt"]._create_for_authorization(
            self.provider_rec,
            self.env.cr.dbname,
            "token-test-session",
            {"d": self.env.cr.dbname, "p": self.provider_rec.id, "r": "/odoo"},
            False,
            BASE_URL + "/auth_oauth/signin",
        )
        return self.env["auth.oidc.login.attempt"].claim_from_callback(
            state, self.env.cr.dbname, "token-test-session"
        )

    def _pending_callback_attempt(self):
        """Create one pending attempt bound to the MockRequest browser session."""
        return self.env["auth.oidc.login.attempt"]._create_for_authorization(
            self.provider_rec,
            self.env.cr.dbname,
            "auth-oidc-test-session",
            {"d": self.env.cr.dbname, "p": self.provider_rec.id, "r": "/odoo"},
            False,
            BASE_URL + "/auth_oauth/signin",
        )

    def test_login_context_is_immutable_and_contains_only_safe_identifiers(self):
        """Test the downstream context excludes every attempt secret and record."""
        attempt, _state = self._pending_callback_attempt()
        attempt.website_id = 42
        login_context = VerifiedOIDCLoginContext.from_attempt(attempt)
        self.assertEqual(login_context.attempt_id, attempt.id)
        self.assertEqual(login_context.website_id, 42)
        self.assertEqual(
            set(login_context.__dataclass_fields__), {"attempt_id", "website_id"}
        )
        for forbidden in (
            "attempt",
            "database_name",
            "session_fingerprint",
            "callback_uri",
            "nonce",
            "code_verifier",
            "access_token",
            "claims",
        ):
            self.assertFalse(hasattr(login_context, forbidden))
        with self.assertRaises(FrozenInstanceError):
            login_context.website_id = 7

    def test_login_context_normalizes_missing_website_to_none(self):
        """Test a missing initiating website has one explicit representation."""
        attempt, _state = self._pending_callback_attempt()
        self.assertIsNone(VerifiedOIDCLoginContext.from_attempt(attempt).website_id)

    @responses.activate
    def test_policy_hook_receives_login_context_and_sanitized_native_params(self):
        """Test the four-argument hook receives only explicit trusted values."""
        user = self._prepare_login_test_user()
        attempt = self._claimed_attempt()
        attempt.website_id = 42
        self._prepare_login_test_responses(attempt)
        with patch.object(
            ResUsers, "_auth_oidc_signin", autospec=True, return_value=user.login
        ) as signin_hook:
            self.env["res.users"].auth_oauth(
                self.provider_rec.id,
                {"_auth_oidc_attempt_id": attempt.id, "code": "code-sentinel"},
            )
        _users, provider, _principal, login_context, native_params = (
            signin_hook.call_args.args
        )
        self.assertEqual(provider, self.provider_rec.id)
        self.assertEqual(login_context, VerifiedOIDCLoginContext(attempt.id, 42))
        self.assertEqual(set(native_params), {"access_token", "state"})
        self.assertNotIn("code-sentinel", native_params.values())

    def _prepare_login_test_responses(
        self,
        attempt,
        claims=None,
        access_token="42",
        headers=None,
        signing_key=None,
        algorithm="RS256",
        jwks=None,
        token_status=200,
        include_access_token=True,
        include_id_token=True,
    ):
        """Mock one token/JWKS exchange with a complete signed ID token."""
        now = int(time.time())
        payload = {
            "sub": "test-subject",
            "iss": self.provider_rec.issuer,
            "aud": self.provider_rec.client_id,
            "exp": now + 300,
            "nbf": now - 1,
            "iat": now,
            "nonce": attempt.nonce,
        }
        payload.update(claims or {})
        if token_status != 200:
            responses.add(
                responses.POST,
                "http://localhost:8080/auth/realms/master/protocol/openid-connect/token",
                status=token_status,
            )
            return
        responses.add(
            responses.POST,
            "http://localhost:8080/auth/realms/master/protocol/openid-connect/token",
            json={
                **({"access_token": access_token} if include_access_token else {}),
                **(
                    {
                        "id_token": jwt.encode(
                            payload,
                            signing_key or self.rsa_key_pem,
                            algorithm=algorithm,
                            headers=(
                                headers
                                if headers is not None
                                else {"kid": "the_key_id"}
                            ),
                        )
                    }
                    if include_id_token
                    else {}
                ),
            },
        )
        jwk = dict(self.rsa_key_public_jwk, kid="the_key_id")
        responses.add(
            responses.GET,
            "http://localhost:8080/auth/realms/master/protocol/openid-connect/certs",
            json={"keys": jwks if jwks is not None else [jwk]},
        )

    @responses.activate
    def test_login_uses_verified_subject_and_attempt_credentials(self):
        """Test that native OAuth receives only a verified standard subject."""
        user = self._prepare_login_test_user()
        attempt = self._claimed_attempt()
        self._prepare_login_test_responses(attempt, access_token="access-sentinel")
        db, login, token = self.env["res.users"].auth_oauth(
            self.provider_rec.id,
            {"_auth_oidc_attempt_id": attempt.id, "code": "code-sentinel"},
        )
        self.assertEqual(db, self.env.cr.dbname)
        self.assertEqual(token, "access-sentinel")
        self.assertEqual(login, user.login)
        attempt.invalidate_recordset(["status"])
        self.assertEqual(attempt.status, "consumed")

    @responses.activate
    def test_finalizer_receives_exact_user_before_attempt_consumption(self):
        """Test the downstream finalizer receives the verified principal once."""
        user = self._prepare_login_test_user()
        attempt = self._claimed_attempt()
        self._prepare_login_test_responses(attempt)

        def finalizer(_users, provider, principal, login_context, final_user):
            attempt.invalidate_recordset(["status"])
            self.assertEqual(attempt.status, "claimed")
            self.assertEqual(provider, self.provider_rec)
            self.assertEqual(principal.subject, "test-subject")
            self.assertEqual(login_context.attempt_id, attempt.id)
            self.assertEqual(final_user, user)

        with patch.object(
            ResUsers,
            "_auth_oidc_finalize_user_provisioning",
            autospec=True,
            side_effect=finalizer,
        ) as finalizer_hook:
            _database, login, _token = self.env["res.users"].auth_oauth(
                self.provider_rec.id,
                {"_auth_oidc_attempt_id": attempt.id, "code": "code-sentinel"},
            )

        self.assertEqual(login, user.login)
        finalizer_hook.assert_called_once()
        attempt.invalidate_recordset(["status"])
        self.assertEqual(attempt.status, "consumed")

    @responses.activate
    def test_finalizer_failure_rolls_back_native_signin_and_callback(self):
        """Test a finalizer failure rolls back credential writes and reaches login."""
        user = self._prepare_login_test_user()
        user.oauth_access_token = "previous-token"
        attempt, state = self._pending_callback_attempt()
        self._prepare_login_test_responses(attempt, access_token="new-token")

        with (
            MockRequest(self.env) as mock_request,
            patch.object(
                ResUsers,
                "_auth_oidc_finalize_user_provisioning",
                autospec=True,
                side_effect=OIDCAuthenticationError("finalizer_failed"),
            ),
        ):
            response = self._signin_controller_boundary(
                state=state, code="code-sentinel"
            )
            self.assertTrue(mock_request.session["auth_oidc_error"])

        user.invalidate_recordset(["oauth_access_token"])
        self.assertEqual(user.oauth_access_token, "previous-token")
        attempt.invalidate_recordset(["status"])
        self.assertEqual(attempt.status, "failed")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.location, "/web/login")

    @responses.activate
    def test_finalizer_requires_matching_exact_identity_login(self):
        """Test a callback cannot finalize a different user login."""
        self._prepare_login_test_user()
        attempt, state = self._pending_callback_attempt()
        self._prepare_login_test_responses(attempt)

        with (
            MockRequest(self.env) as mock_request,
            patch.object(
                ResUsers,
                "_auth_oidc_signin",
                autospec=True,
                return_value="different-login",
            ),
            patch.object(
                ResUsers, "_auth_oidc_finalize_user_provisioning", autospec=True
            ) as finalizer_hook,
        ):
            response = self._signin_controller_boundary(
                state=state, code="code-sentinel"
            )
            self.assertTrue(mock_request.session["auth_oidc_error"])

        finalizer_hook.assert_not_called()
        attempt.invalidate_recordset(["status"])
        self.assertEqual(attempt.status, "failed")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.location, "/web/login")

    def test_claimed_provider_denial_is_normalized_after_native_handling(self):
        """Test provider denial reaches native OAuth then returns fixed login."""
        attempt, state = self._pending_callback_attempt()
        with MockRequest(self.env) as mock_request:
            response = self._signin_controller_boundary(
                state=state, error="provider-error-sentinel"
            )
            self.assertTrue(mock_request.session["auth_oidc_error"])
        attempt.invalidate_recordset(["status"])
        self.assertEqual(attempt.status, "failed")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.location, "/web/login")
        self.assertNotIn("provider-error-sentinel", response.location)
        self.assertNotIn("oauth_error", response.location)

    @responses.activate
    def test_claimed_exchange_failure_is_normalized_after_native_handling(self):
        """Test token exchange failure reaches native OAuth then uses fixed login."""
        attempt, state = self._pending_callback_attempt()
        self._prepare_login_test_responses(attempt, token_status=500)
        with MockRequest(self.env) as mock_request:
            response = self._signin_controller_boundary(
                state=state, code="code-sentinel"
            )
            self.assertTrue(mock_request.session["auth_oidc_error"])
        attempt.invalidate_recordset(["status"])
        self.assertEqual(attempt.status, "failed")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.location, "/web/login")
        self.assertNotIn("code-sentinel", response.location)

    def test_native_callback_failure_is_rewritten_and_success_is_preserved(self):
        """Test only a native OAuth error redirect is replaced after attempt claim."""
        failing_attempt, failing_state = self._pending_callback_attempt()
        with MockRequest(self.env) as mock_request:
            native_failure = mock_request.redirect("/web/login?oauth_error=2", 303)
            with patch.object(OAuthController, "signin", return_value=native_failure):
                response = self._signin_controller_boundary(state=failing_state)
            self.assertTrue(mock_request.session["auth_oidc_error"])
        self.assertEqual(response.location, "/web/login")

        success_attempt, success_state = self._pending_callback_attempt()
        with MockRequest(self.env) as mock_request:
            native_success = mock_request.redirect("/odoo", 303)
            with patch.object(OAuthController, "signin", return_value=native_success):
                response = self._signin_controller_boundary(state=success_state)
            self.assertNotIn("auth_oidc_error", mock_request.session)
        self.assertEqual(response.location, "/odoo")

    @responses.activate
    def test_strict_claim_failures_mark_the_attempt_failed(self):
        """Test each claim contract failure denies before native sign-in."""
        now = int(time.time())
        self.provider_rec.tenant_id = "tenant-sentinel"
        failures = {
            "issuer": {"iss": "wrong-issuer"},
            "audience": {"aud": "wrong-audience"},
            "exp": {"exp": None},
            "nbf": {"nbf": None},
            "iat": {"iat": None},
            "nonce": {"nonce": "wrong-nonce"},
            "missing_tenant": {"tid": None},
            "tenant": {"tid": "wrong-tenant"},
            "subject": {"sub": ""},
            "multi_audience_azp": {"aud": [self.provider_rec.client_id, "other"]},
            "expired": {"exp": now - 1000},
            "future_nbf": {"nbf": now + 1000},
            "future_iat": {"iat": now + 1000},
        }
        for name, claims in failures.items():
            with self.subTest(name=name):
                attempt = self._claimed_attempt()
                self._prepare_login_test_responses(attempt, claims=claims)
                self._auth_oauth_denied(
                    self.provider_rec.id,
                    {"_auth_oidc_attempt_id": attempt.id, "code": "code-sentinel"},
                )
                attempt.invalidate_recordset(["status"])
                self.assertEqual(attempt.status, "failed")
                responses.reset()

    @staticmethod
    def _at_hash(access_token):
        """Return the OpenID Connect RS256 access-token hash for a test token."""
        digest = hashlib.sha256(access_token.encode()).digest()
        return (
            base64.urlsafe_b64encode(digest[: len(digest) // 2]).rstrip(b"=").decode()
        )

    @responses.activate
    def test_access_token_hash_is_validated(self):
        """Test a matching at_hash is accepted and a mismatching hash is terminal."""
        user = self._prepare_login_test_user()
        access_token = "access-token-sentinel"
        valid_attempt = self._claimed_attempt()
        self._prepare_login_test_responses(
            valid_attempt,
            access_token=access_token,
            claims={"at_hash": self._at_hash(access_token)},
        )
        _, login, _ = self.env["res.users"].auth_oauth(
            self.provider_rec.id,
            {"_auth_oidc_attempt_id": valid_attempt.id, "code": "code-sentinel"},
        )
        self.assertEqual(login, user.login)
        responses.reset()

        invalid_attempt = self._claimed_attempt()
        self._prepare_login_test_responses(
            invalid_attempt,
            access_token=access_token,
            claims={"at_hash": "wrong-hash"},
        )
        self._auth_oauth_denied(
            self.provider_rec.id,
            {"_auth_oidc_attempt_id": invalid_attempt.id, "code": "code-sentinel"},
        )
        invalid_attempt.invalidate_recordset(["status"])
        self.assertEqual(invalid_attempt.status, "failed")

    @responses.activate
    def test_missing_token_values_mark_attempt_failed(self):
        """Test the token response must contain both required token values."""
        for name, kwargs in {
            "access_token": {"include_access_token": False},
            "id_token": {"include_id_token": False},
        }.items():
            with self.subTest(name=name):
                attempt = self._claimed_attempt()
                self._prepare_login_test_responses(attempt, **kwargs)
                self._auth_oauth_denied(
                    self.provider_rec.id,
                    {"_auth_oidc_attempt_id": attempt.id, "code": "code-sentinel"},
                )
                attempt.invalidate_recordset(["status"])
                self.assertEqual(attempt.status, "failed")
                responses.reset()

    @responses.activate
    def test_key_algorithm_and_signature_failures_mark_attempt_failed(self):
        """Test key selection, allowlist, and signature failures are terminal."""
        failures = {
            "missing_key": {"headers": {"kid": "missing-key"}},
            "missing_key_id": {"headers": {}},
            "algorithm": {"algorithm": "HS256", "signing_key": "shared-secret"},
            "signature": {"signing_key": self.second_key_pem},
        }
        for name, kwargs in failures.items():
            with self.subTest(name=name):
                attempt = self._claimed_attempt()
                self._prepare_login_test_responses(attempt, **kwargs)
                self._auth_oauth_denied(
                    self.provider_rec.id,
                    {"_auth_oidc_attempt_id": attempt.id, "code": "code-sentinel"},
                )
                attempt.invalidate_recordset(["status"])
                self.assertEqual(attempt.status, "failed")
                responses.reset()

    @responses.activate
    def test_jwks_rotation_tries_matching_keys_until_signature_validates(self):
        """Test same-key-ID rotation accepts a later valid JWKS key."""
        user = self._prepare_login_test_user()
        attempt = self._claimed_attempt()
        old_jwk = dict(self.second_key_public_jwk, kid="the_key_id")
        current_jwk = dict(self.rsa_key_public_jwk, kid="the_key_id")
        self._prepare_login_test_responses(attempt, jwks=[old_jwk, current_jwk])
        _, login, _ = self.env["res.users"].auth_oauth(
            self.provider_rec.id,
            {"_auth_oidc_attempt_id": attempt.id, "code": "code-sentinel"},
        )
        self.assertEqual(login, user.login)

    def test_wrong_attempt_provider_is_rejected_before_exchange(self):
        """Test a claimed attempt cannot be used with a different provider."""
        attempt = self._claimed_attempt()
        other_provider = self.env["auth.oauth.provider"].create(
            {
                "name": "Other OpenID Connect Provider",
                "flow": "id_token_code",
                "enabled": False,
                "client_id": "other-client",
                "auth_endpoint": "https://example.invalid/authorize",
                "body": "Other OpenID Connect Provider",
            }
        )
        attempt.write({"provider_id": other_provider.id})
        with self.assertRaises(AccessDenied):
            self.env["res.users"].auth_oauth(
                self.provider_rec.id,
                {"_auth_oidc_attempt_id": attempt.id, "code": "code-sentinel"},
            )
        with self.assertRaises(AccessDenied):
            self.env["res.users"].auth_oauth(
                self.provider_rec.id,
                {
                    "_auth_oidc_attempt_id": attempt.id + 1000000,
                    "code": "code-sentinel",
                },
            )

    def test_legacy_or_unknown_provider_never_falls_back_to_native_validation(self):
        """Test injected legacy and unknown flows deny before native OAuth."""
        self.env.cr.execute(
            "UPDATE auth_oauth_provider SET flow = 'id_token' WHERE id = %s",
            [self.provider_rec.id],
        )
        self.provider_rec.invalidate_recordset(["flow"])
        with self.assertRaises(AccessDenied):
            self.env["res.users"].auth_oauth(self.provider_rec.id, {})
        with self.assertRaises(AccessDenied):
            self.env["res.users"].auth_oauth(self.provider_rec.id + 1000000, {})

    def test_provider_configuration_and_clock_skew_are_constrained(self):
        """Test enabled OIDC configuration and clock skew fail at the ORM boundary."""
        with self.assertRaises(ValidationError):
            self.provider_rec.write({"clock_skew_seconds": 301})
        with self.assertRaises(ValidationError):
            self.provider_rec.write({"allowed_algorithms": "HS256"})
        with self.assertRaises(ValidationError):
            self.env["auth.oauth.provider"].create(
                {
                    "name": "Incomplete OpenID Connect Provider",
                    "flow": "id_token_code",
                    "enabled": True,
                    "auth_endpoint": "https://example.invalid/authorize",
                    "body": "Incomplete OpenID Connect Provider",
                }
            )

    def test_expected_failure_log_redacts_callback_sentinels(self):
        """Test typed protocol failures do not log callback or provider text."""
        attempt = self._claimed_attempt()
        with (
            self.assertRaises(AccessDenied),
            self.assertLogs(
                "odoo.addons.auth_oidc.models.res_users", level=logging.INFO
            ) as logs,
        ):
            self.env["res.users"].auth_oauth(
                self.provider_rec.id,
                {
                    "_auth_oidc_attempt_id": attempt.id,
                    "error": "error-sentinel",
                    "code": "code-sentinel",
                },
            )
        output = "\n".join(logs.output)
        for sentinel in ("error-sentinel", "code-sentinel", attempt.nonce):
            self.assertNotIn(sentinel, output)

    def test_failure_notification_is_frozen_and_contains_no_secret_fields(self):
        """Test the notification shape contains only reason and attempt correlation."""
        failure = OIDCFailure(reason="credential_rejected", attempt_id=42)
        self.assertEqual(set(failure.__dataclass_fields__), {"reason", "attempt_id"})
        for forbidden in (
            "message",
            "description",
            "response",
            "body",
            "code",
            "token",
            "nonce",
            "claims",
        ):
            self.assertFalse(hasattr(failure, forbidden))
        with self.assertRaises(FrozenInstanceError):
            failure.reason = "changed"

    @responses.activate
    def test_invalid_client_is_classified_and_notifies_once(self):
        """Test exact token JSON invalid_client becomes one credential notification."""
        attempt = self._claimed_attempt()
        responses.add(
            responses.POST,
            self.provider_rec.token_endpoint,
            status=401,
            json={
                "error": "invalid_client",
                "error_description": "secret-description-sentinel",
            },
        )
        with (
            patch.object(ResUsers, "_auth_oidc_failure", autospec=True) as failure_hook,
            self.assertRaises(AccessDenied),
        ):
            self.env["res.users"].auth_oauth(
                self.provider_rec.id,
                {"_auth_oidc_attempt_id": attempt.id, "code": "code-sentinel"},
            )
        failure_hook.assert_called_once()
        _users, provider, failure = failure_hook.call_args.args
        self.assertEqual(provider, self.provider_rec.id)
        self.assertEqual(failure, OIDCFailure("credential_rejected", attempt.id))

    @responses.activate
    def test_other_token_error_keeps_generic_exchange_classification(self):
        """Test provider errors other than exact invalid_client stay generic."""
        attempt = self._claimed_attempt()
        responses.add(
            responses.POST,
            self.provider_rec.token_endpoint,
            status=400,
            json={"error": "invalid_grant", "error_description": "secret-sentinel"},
        )
        with (
            patch.object(ResUsers, "_auth_oidc_failure", autospec=True) as failure_hook,
            self.assertRaises(AccessDenied),
        ):
            self.env["res.users"].auth_oauth(
                self.provider_rec.id,
                {"_auth_oidc_attempt_id": attempt.id, "code": "code-sentinel"},
            )
        failure = failure_hook.call_args.args[-1]
        self.assertEqual(failure.reason, "token_exchange_failed")

    @responses.activate
    def test_failure_hook_exception_preserves_access_denied(self):
        """Test an extension-hook exception cannot replace generic auth failure."""
        attempt = self._claimed_attempt()
        with (
            patch.object(
                ResUsers,
                "_auth_oidc_failure",
                autospec=True,
                side_effect=RuntimeError("hook-secret-sentinel"),
            ),
            self.assertRaises(AccessDenied),
            self.assertLogs(
                "odoo.addons.auth_oidc.models.res_users", level=logging.ERROR
            ) as logs,
        ):
            self.env["res.users"].auth_oauth(
                self.provider_rec.id,
                {
                    "_auth_oidc_attempt_id": attempt.id,
                    "error": "provider-error-sentinel",
                },
            )
        self.assertNotIn("hook-secret-sentinel", "\n".join(logs.output))

    @responses.activate
    def test_provider_denial_and_exchange_failure_mark_attempt_failed(self):
        """Test provider and token-endpoint errors are terminal and redacted."""
        denied_attempt = self._claimed_attempt()
        self._auth_oauth_denied(
            self.provider_rec.id,
            {
                "_auth_oidc_attempt_id": denied_attempt.id,
                "error": "provider-error-sentinel",
            },
        )
        denied_attempt.invalidate_recordset(["status"])
        self.assertEqual(denied_attempt.status, "failed")

        exchange_attempt = self._claimed_attempt()
        self._prepare_login_test_responses(exchange_attempt, token_status=500)
        self._auth_oauth_denied(
            self.provider_rec.id,
            {"_auth_oidc_attempt_id": exchange_attempt.id, "code": "code-sentinel"},
        )
        exchange_attempt.invalidate_recordset(["status"])
        self.assertEqual(exchange_attempt.status, "failed")

    def _drive_real_http_login_start(self):
        """Load /web/login for real and follow its OIDC link for real.

        Returns the pending attempt created by the real ``/auth_oidc/start``
        request, plus the anonymous session id observed before it.
        """
        login_page = self.url_open("/web/login")
        login_page.raise_for_status()
        anonymous_sid = self.opener.cookies.get("session_id")
        self.assertTrue(anonymous_sid, "HttpCase opener must carry a session id")
        match = re.search(r'href="(/auth_oidc/start\?intent=[^"]+)"', login_page.text)
        self.assertTrue(match, "no /auth_oidc/start link rendered on /web/login")
        start_url = match.group(1).replace("&amp;", "&")

        start_response = self.url_open(start_url, allow_redirects=False)
        self.assertEqual(start_response.status_code, 303)
        self.assertTrue(
            start_response.headers["Location"].startswith(
                self.provider_rec.auth_endpoint
            )
        )
        state = parse_qs(urlparse(start_response.headers["Location"]).query)[
            "state"
        ][0]
        attempt = self.env["auth.oidc.login.attempt"].search(
            [("state_digest", "=", hashlib.sha256(state.encode()).hexdigest())]
        )
        self.assertTrue(attempt, "no attempt row created by the real start route")
        return attempt, state, anonymous_sid

    @responses.activate
    def _assert_real_http_success_rotates_session(self, user, subject):
        """Drive one full routed OIDC success and assert real rotation.

        Only the token and JWKS endpoints are mocked; ``/web/login``,
        ``/auth_oidc/start``, and ``/auth_oauth/signin`` are hit for real
        through the HttpCase opener, so this proves what a direct
        controller call cannot: that a genuinely different session id is
        stored and cookied after native ``Session.authenticate()`` and
        ``finalize()`` run inside real post-dispatch.
        """
        responses.add_passthru(self.base_url())
        self.env["auth.oauth.provider"].search(
            [("client_id", "!=", "auth_oidc-test")]
        ).write({"enabled": False})

        attempt, state, anonymous_sid = self._drive_real_http_login_start()
        self._prepare_login_test_responses(attempt, claims={"sub": subject})

        signin_response = self.url_open(
            "/auth_oauth/signin?{}".format(
                urlencode({"state": state, "code": "code-sentinel"})
            ),
            allow_redirects=False,
        )

        self.assertEqual(signin_response.status_code, 303)
        attempt.invalidate_recordset(["status"])
        self.assertEqual(attempt.status, "consumed")

        new_sid = self.opener.cookies.get("session_id")
        self.assertTrue(new_sid)
        self.assertNotEqual(
            new_sid,
            anonymous_sid,
            "session id did not rotate across the real routed OIDC callback",
        )
        stored_session = odoo.http.root.session_store.get(new_sid)
        self.assertEqual(stored_session.uid, user.id)

        check_response = self.url_open(
            "/web/session/check",
            headers={"Content-Type": "application/json"},
            data="{}",
        )
        check_response.raise_for_status()
        return signin_response

    def test_internal_user_real_http_success_path_rotates_session(self):
        """Test a real routed OIDC success for an internal user rotates the SID."""
        user = self._prepare_login_test_user()
        self.assertTrue(user._is_internal())
        response = self._assert_real_http_success_rotates_session(
            user, subject="test-subject"
        )
        self.assertEqual(
            self.parse_http_location(response.headers["Location"]).path, "/web"
        )

    def test_portal_user_real_http_success_path_rotates_session(self):
        """Test a real routed OIDC success for a portal user rotates the SID."""
        portal_user = (
            self.env["res.users"]
            .with_context(no_reset_password=True)
            .create(
                {
                    "name": "OIDC portal user",
                    "login": "oidc-portal-user@example.test",
                    "email": "oidc-portal-user@example.test",
                    "groups_id": [(6, 0, [self.env.ref("base.group_portal").id])],
                    "oauth_provider_id": self.provider_rec.id,
                    "oauth_uid": "portal-test-subject",
                }
            )
        )
        self.assertFalse(portal_user._is_internal())
        response = self._assert_real_http_success_rotates_session(
            portal_user, subject="portal-test-subject"
        )
        self.assertEqual(
            self.parse_http_location(response.headers["Location"]).path, "/"
        )
