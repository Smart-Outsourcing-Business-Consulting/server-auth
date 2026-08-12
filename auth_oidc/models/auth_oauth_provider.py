# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# Copyright 2026 Smart Outsourcing Business Consulting
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

"""Strict OpenID Connect provider configuration and token validation."""

import time
from types import MappingProxyType

import requests

from odoo import api, fields, models
from odoo.exceptions import ValidationError

try:
    from jose import jwt
    from jose.exceptions import JWSError, JWTError
except ImportError:
    jwt = None
    JWSError = JWTError = Exception


class OIDCAuthenticationError(Exception):
    """A redacted, expected OIDC protocol or claim-validation failure."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


class VerifiedOIDCClaims:
    """Immutable claims validated by this adapter's OIDC boundary."""

    __slots__ = ("_claims",)

    def __init__(self, claims):
        self._claims = MappingProxyType(dict(claims))

    @property
    def claims(self):
        """Return the read-only, fully validated claim mapping."""
        return self._claims

    @property
    def subject(self):
        """Return the verified provider-scoped standard subject."""
        return self._claims["sub"]


class AuthOauthProvider(models.Model):
    """Add strict authorization-code OpenID Connect capabilities to OAuth."""

    _inherit = "auth.oauth.provider"

    flow = fields.Selection(
        [
            ("access_token", "OAuth2"),
            ("id_token_code", "OpenID Connect (authorization code flow)"),
        ],
        string="Auth Flow",
        required=True,
        default="access_token",
    )
    client_secret = fields.Char(
        help="Used for confidential authorization-code clients.",
    )
    validation_endpoint = fields.Char(required=False)
    token_endpoint = fields.Char(
        string="Token URL", help="Required for OpenID Connect authorization code flow."
    )
    jwks_uri = fields.Char(string="JWKS URL", help="Required for OpenID Connect.")
    issuer = fields.Char(help="Exact issuer accepted from ID tokens.")
    tenant_id = fields.Char(
        help="Optional exact Entra tenant ID accepted from ID tokens."
    )
    allowed_algorithms = fields.Char(default="RS256", required=True)
    clock_skew_seconds = fields.Integer(default=60, required=True)

    @api.constrains(
        "enabled",
        "flow",
        "client_id",
        "scope",
        "token_endpoint",
        "jwks_uri",
        "issuer",
        "allowed_algorithms",
        "clock_skew_seconds",
    )
    def _check_enabled_oidc_configuration(self):
        """Reject enabled OIDC rows that cannot satisfy the strict contract."""
        for provider in self:
            if provider.flow != "id_token_code":
                continue
            if not 0 <= provider.clock_skew_seconds <= 300:
                raise ValidationError(
                    provider.env._(
                        "OpenID Connect clock skew must be between 0 and 300 seconds."
                    )
                )
            if not provider.enabled:
                continue
            if (
                not all(
                    (
                        provider.client_id,
                        provider.token_endpoint,
                        provider.jwks_uri,
                        provider.issuer,
                    )
                )
                or "openid" not in (provider.scope or "").split()
            ):
                raise ValidationError(
                    provider.env._(
                        "Enabled OpenID Connect providers require client ID, OpenID "
                        "scope, token URL, JWKS URL, and exact issuer."
                    )
                )
            try:
                provider._allowed_algorithms()
            except OIDCAuthenticationError as error:
                raise ValidationError(
                    provider.env._(
                        "Enabled OpenID Connect provider algorithm configuration is "
                        "invalid."
                    )
                ) from error

    def _allowed_algorithms(self):
        """Return the configured non-empty asymmetric JWT algorithm allowlist."""
        self.ensure_one()
        algorithms = [
            algorithm.strip()
            for algorithm in (self.allowed_algorithms or "").split(",")
            if algorithm.strip()
        ]
        if not algorithms or any(
            not algorithm.startswith(("RS", "ES", "PS")) for algorithm in algorithms
        ):
            raise OIDCAuthenticationError("invalid_algorithm_configuration")
        return algorithms

    def _get_keys(self, kid):
        """Fetch the configured JWKS and select keys by the trusted header key ID."""
        self.ensure_one()
        if not self.jwks_uri or not kid:
            raise OIDCAuthenticationError("missing_jwks_key")
        try:
            response = requests.get(self.jwks_uri, timeout=10)
            response.raise_for_status()
            keys = response.json().get("keys", [])
        except (requests.RequestException, ValueError, TypeError):
            raise OIDCAuthenticationError("jwks_unavailable") from None
        selected = [key for key in keys if key.get("kid") == kid]
        if not selected:
            raise OIDCAuthenticationError("jwks_key_not_found")
        return selected

    def exchange_authorization_code(self, attempt, code):
        """Exchange one authorization code using only its stored PKCE material."""
        self.ensure_one()
        if not isinstance(code, str) or not code:
            raise OIDCAuthenticationError("missing_authorization_code")
        if not self.token_endpoint:
            raise OIDCAuthenticationError("missing_token_endpoint")
        auth = (self.client_id, self.client_secret) if self.client_secret else None
        try:
            response = requests.post(
                self.token_endpoint,
                data={
                    "client_id": self.client_id,
                    "grant_type": "authorization_code",
                    "code": code,
                    "code_verifier": attempt.code_verifier,
                    "redirect_uri": attempt.callback_uri,
                },
                auth=auth,
                timeout=10,
            )
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError
            if payload.get("error") == "invalid_client":
                raise OIDCAuthenticationError("credential_rejected")
            response.raise_for_status()
        except OIDCAuthenticationError:
            raise
        except (requests.RequestException, ValueError, TypeError):
            raise OIDCAuthenticationError("token_exchange_failed") from None
        access_token = payload.get("access_token")
        id_token = payload.get("id_token")
        if not isinstance(access_token, str) or not access_token:
            raise OIDCAuthenticationError("missing_access_token")
        if not isinstance(id_token, str) or not id_token:
            raise OIDCAuthenticationError("missing_id_token")
        return access_token, id_token

    def verify_id_token(self, id_token, access_token, attempt):
        """Return immutable claims after signature and complete semantic checks."""
        self.ensure_one()
        if jwt is None:
            raise OIDCAuthenticationError("jwt_library_unavailable")
        if not self.issuer or not self.client_id:
            raise OIDCAuthenticationError("missing_provider_claim_configuration")
        try:
            header = jwt.get_unverified_header(id_token)
        except (JWTError, JWSError, ValueError, TypeError):
            raise OIDCAuthenticationError("invalid_token_header") from None
        algorithms = self._allowed_algorithms()
        if header.get("alg") not in algorithms:
            raise OIDCAuthenticationError("algorithm_not_allowed")
        claims = self._decode_with_jwks(
            id_token, access_token, header.get("kid"), algorithms
        )
        self._check_claims(claims, attempt)
        return VerifiedOIDCClaims(claims)

    def _decode_with_jwks(self, id_token, access_token, kid, algorithms):
        """Decode a signed ID token against one of the current matching JWKS keys."""
        for key in self._get_keys(kid):
            try:
                return jwt.decode(
                    id_token,
                    key,
                    algorithms=algorithms,
                    audience=self.client_id,
                    access_token=access_token,
                    issuer=self.issuer,
                    options={
                        "require_exp": True,
                        "require_nbf": True,
                        "require_iat": True,
                        "require_iss": True,
                        "require_aud": True,
                        "verify_aud": True,
                        "verify_iss": True,
                        "leeway": self.clock_skew_seconds,
                    },
                )
            except (JWTError, JWSError, ValueError, TypeError):
                continue
        raise OIDCAuthenticationError("token_signature_or_standard_claims_invalid")

    def _check_claims(self, claims, attempt):
        """Enforce OIDC claims that require this attempt or provider configuration."""
        required_times = ("exp", "nbf", "iat")
        if not all(
            isinstance(claims.get(name), (int, float)) for name in required_times
        ):
            raise OIDCAuthenticationError("invalid_time_claim")
        now = time.time()
        skew = self.clock_skew_seconds
        if skew < 0 or claims["exp"] < now - skew or claims["nbf"] > now + skew:
            raise OIDCAuthenticationError("time_claim_outside_allowed_skew")
        if claims["iat"] > now + skew:
            raise OIDCAuthenticationError("issued_in_future")
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if self.client_id not in audiences:
            raise OIDCAuthenticationError("audience_mismatch")
        if len(audiences) > 1 and claims.get("azp") != self.client_id:
            raise OIDCAuthenticationError("authorized_party_mismatch")
        if claims.get("iss") != self.issuer:
            raise OIDCAuthenticationError("issuer_mismatch")
        if claims.get("nonce") != attempt.nonce:
            raise OIDCAuthenticationError("nonce_mismatch")
        if self.tenant_id and claims.get("tid") != self.tenant_id:
            raise OIDCAuthenticationError("tenant_mismatch")
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise OIDCAuthenticationError("missing_subject")

    def init(self):
        """Stop upgrades that retain an implicit-flow provider configuration."""
        self.env.cr.execute(
            "SELECT id FROM auth_oauth_provider WHERE flow = 'id_token' LIMIT 1"
        )
        if self.env.cr.fetchone():
            raise RuntimeError(
                "OpenID Connect implicit flow is unsupported. Change every affected "
                "OAuth provider to authorization-code flow before upgrading auth_oidc."
            )
