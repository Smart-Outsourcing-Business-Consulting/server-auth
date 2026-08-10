# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import base64
import contextlib
import hashlib
import json
import logging
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

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

from ..controllers.main import OpenIDController, OpenIDLogin

BASE_URL = f"http://localhost:{odoo.tools.config['http_port']}"


@contextlib.contextmanager
def MockRequest(env):
    with _MockRequest(env) as request:
        request.httprequest.url_root = BASE_URL + "/"
        request.params = {}
        request.session.db = env.cr.dbname
        request.session.sid = "auth-oidc-test-session"
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

    def test_auth_link(self):
        """Test that the authentication link is correct."""
        # disable existing providers except our test provider
        self.env["auth.oauth.provider"].search(
            [("client_id", "!=", "auth_oidc-test")]
        ).write(dict(enabled=False))
        with MockRequest(self.env):
            providers = OpenIDLogin().list_providers()
            self.assertEqual(len(providers), 1)
            auth_link = providers[0]["auth_link"]
            assert auth_link.startswith(self.provider_rec.auth_endpoint)
            params = parse_qs(urlparse(auth_link).query)
            self.assertEqual(params["response_type"], ["code"])
            self.assertEqual(params["client_id"], [self.provider_rec.client_id])
            self.assertEqual(params["scope"], ["openid email"])
            self.assertTrue(params["code_challenge"])
            self.assertEqual(params["code_challenge_method"], ["S256"])
            self.assertTrue(params["nonce"])
            self.assertTrue(params["state"])
            self.assertEqual(params["redirect_uri"], [BASE_URL + "/auth_oauth/signin"])
            state = params["state"][0]
            attempt = self.env["auth.oidc.login.attempt"].search(
                [("state_digest", "=", hashlib.sha256(state.encode()).hexdigest())]
            )
            self.assertEqual(attempt.provider_id, self.provider_rec)
            self.assertEqual(attempt.database_name, self.env.cr.dbname)
            self.assertEqual(attempt.status, "pending")
            self.assertEqual(attempt.redirect_path, "/odoo")
            self.assertEqual(attempt.callback_uri, BASE_URL + "/auth_oauth/signin")
            self.assertEqual(params["nonce"], [attempt.nonce])
            self.assertEqual(params["code_challenge"], [attempt.code_challenge()])

    def test_authorization_attempts_are_fresh_and_bind_local_redirect(self):
        """Test that every authorization URL has isolated, local-only state."""
        self.env["auth.oauth.provider"].search(
            [("client_id", "!=", "auth_oidc-test")]
        ).write({"enabled": False})
        with MockRequest(self.env) as mock_request:
            mock_request.params = {"redirect": "/web#home"}
            first_url = OpenIDLogin().list_providers()[0]["auth_link"]
            second_url = OpenIDLogin().list_providers()[0]["auth_link"]

        first_params = parse_qs(urlparse(first_url).query)
        second_params = parse_qs(urlparse(second_url).query)
        self.assertNotEqual(first_params["state"], second_params["state"])
        self.assertNotEqual(first_params["nonce"], second_params["nonce"])
        self.assertNotEqual(
            first_params["code_challenge"], second_params["code_challenge"]
        )
        attempts = self.env["auth.oidc.login.attempt"].search(
            [("provider_id", "=", self.provider_rec.id)], order="id desc", limit=2
        )
        self.assertEqual(attempts.mapped("redirect_path"), ["/web#home", "/web#home"])
        self.assertTrue(all(attempt.code_verifier for attempt in attempts))

    def test_unsafe_redirect_defaults_to_odoo(self):
        """Test that protocol and encoded redirect bypasses are rejected."""
        unsafe_redirects = (
            "https://attacker.invalid/",
            "//attacker.invalid/",
            "/%2f%2fattacker.invalid/",
            "/%5cattacker.invalid/",
            "/%252f%252fattacker.invalid/",
            "/%2525252f%2525252fattacker.invalid/",
            "/web\\attacker",
        )
        for redirect in unsafe_redirects:
            with MockRequest(self.env) as mock_request:
                mock_request.params = {"redirect": redirect}
                auth_link = OpenIDLogin().list_providers()[0]["auth_link"]
            state = parse_qs(urlparse(auth_link).query)["state"][0]
            attempt = self.env["auth.oidc.login.attempt"].search(
                [("state_digest", "=", hashlib.sha256(state.encode()).hexdigest())]
            )
            self.assertEqual(attempt.redirect_path, "/odoo")

    def test_attempt_claim_is_session_bound_and_one_time(self):
        """Test that only the initiating session can atomically claim state."""
        attempt_model = self.env["auth.oidc.login.attempt"]
        attempt, state = attempt_model.create_for_authorization(
            self.provider_rec,
            self.env.cr.dbname,
            "initial-session",
            {"d": self.env.cr.dbname, "p": self.provider_rec.id, "r": "/odoo"},
            "/odoo",
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

    def test_native_shaped_state_cannot_bypass_an_oidc_attempt(self):
        """Test that a native-shaped callback state cannot bypass OIDC correlation."""
        state = json.dumps({"d": self.env.cr.dbname, "p": self.provider_rec.id})
        with MockRequest(self.env) as mock_request:
            response = OpenIDController().signin(state=state)
            self.assertTrue(mock_request.session["auth_oidc_error"])
        self.assertEqual(response.location, "/web/login")
        self.assertNotIn("?", response.location)

    def test_non_ascii_state_fails_at_the_fixed_login_destination(self):
        """Test malformed callback state never raises or remains in the URL."""
        with MockRequest(self.env) as mock_request:
            response = OpenIDController().signin(state="not-ascii-€")
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
        attempt, state = self.env["auth.oidc.login.attempt"].create_for_authorization(
            self.provider_rec,
            self.env.cr.dbname,
            "token-test-session",
            {"d": self.env.cr.dbname, "p": self.provider_rec.id, "r": "/odoo"},
            "/odoo",
            False,
            BASE_URL + "/auth_oauth/signin",
        )
        return self.env["auth.oidc.login.attempt"].claim_from_callback(
            state, self.env.cr.dbname, "token-test-session"
        )

    def _pending_callback_attempt(self):
        """Create one pending attempt bound to the MockRequest browser session."""
        return self.env["auth.oidc.login.attempt"].create_for_authorization(
            self.provider_rec,
            self.env.cr.dbname,
            "auth-oidc-test-session",
            {"d": self.env.cr.dbname, "p": self.provider_rec.id, "r": "/odoo"},
            "/odoo",
            False,
            BASE_URL + "/auth_oauth/signin",
        )

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

    def test_claimed_provider_denial_is_normalized_after_native_handling(self):
        """Test provider denial reaches native OAuth then returns fixed login."""
        attempt, state = self._pending_callback_attempt()
        with MockRequest(self.env) as mock_request:
            response = OpenIDController().signin(
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
            response = OpenIDController().signin(state=state, code="code-sentinel")
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
                response = OpenIDController().signin(state=failing_state)
            self.assertTrue(mock_request.session["auth_oidc_error"])
        self.assertEqual(response.location, "/web/login")

        success_attempt, success_state = self._pending_callback_attempt()
        with MockRequest(self.env) as mock_request:
            native_success = mock_request.redirect("/odoo", 303)
            with patch.object(OAuthController, "signin", return_value=native_success):
                response = OpenIDController().signin(state=success_state)
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
                with self.assertRaises(AccessDenied):
                    self.env["res.users"].auth_oauth(
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
        with self.assertRaises(AccessDenied):
            self.env["res.users"].auth_oauth(
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
                with self.assertRaises(AccessDenied):
                    self.env["res.users"].auth_oauth(
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
                with self.assertRaises(AccessDenied):
                    self.env["res.users"].auth_oauth(
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

    @responses.activate
    def test_provider_denial_and_exchange_failure_mark_attempt_failed(self):
        """Test provider and token-endpoint errors are terminal and redacted."""
        denied_attempt = self._claimed_attempt()
        with self.assertRaises(AccessDenied):
            self.env["res.users"].auth_oauth(
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
        with self.assertRaises(AccessDenied):
            self.env["res.users"].auth_oauth(
                self.provider_rec.id,
                {"_auth_oidc_attempt_id": exchange_attempt.id, "code": "code-sentinel"},
            )
        exchange_attempt.invalidate_recordset(["status"])
        self.assertEqual(exchange_attempt.status, "failed")
