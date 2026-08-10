# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

import contextlib
import hashlib
import json
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import responses
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt
from jose.utils import long_to_base64

import odoo
from odoo.tests import common

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
        _, cls.second_key_public_pem, _ = cls._generate_key()

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
        self.assertEqual(response.location, "/odoo")

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

    def _prepare_login_test_responses(self, attempt, claims=None, access_token="42"):
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
        responses.add(
            responses.POST,
            "http://localhost:8080/auth/realms/master/protocol/openid-connect/token",
            json={
                "access_token": access_token,
                "id_token": jwt.encode(
                    payload,
                    self.rsa_key_pem,
                    algorithm="RS256",
                    headers={"kid": "the_key_id"},
                ),
            },
        )
        jwk = dict(self.rsa_key_public_jwk, kid="the_key_id")
        responses.add(
            responses.GET,
            "http://localhost:8080/auth/realms/master/protocol/openid-connect/certs",
            json={"keys": [jwk]},
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
