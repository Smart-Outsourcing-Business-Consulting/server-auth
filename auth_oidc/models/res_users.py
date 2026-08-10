# Copyright 2016 ICTSTUDIO <http://www.ictstudio.eu>
# Copyright 2021 ACSONE SA/NV <https://acsone.eu>
# Copyright 2026 Smart Outsourcing Business Consulting
# License: AGPL-3.0 or later (http://www.gnu.org/licenses/agpl)

"""Native Odoo sign-in hand-off for strictly verified OIDC principals."""

import json
import logging
from dataclasses import dataclass
from types import MappingProxyType

from odoo import api, fields, models
from odoo.exceptions import AccessDenied

from .auth_oauth_provider import OIDCAuthenticationError

_logger = logging.getLogger(__name__)


def _freeze_claim_value(value):
    """Recursively make a JSON-like verified claim value immutable."""
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_claim_value(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_claim_value(item) for item in value)
    return value


@dataclass(frozen=True)
class VerifiedOIDCPrincipal:
    """The immutable OIDC identity contract exposed to downstream policy."""

    provider_id: int
    subject: str
    issuer: str
    tenant_id: str | None
    claims: MappingProxyType

    @classmethod
    def from_verified_claims(cls, provider_id, verified_claims):
        """Create the only downstream principal from adapter-validated claims."""
        claims = verified_claims.claims
        return cls(
            provider_id=provider_id,
            subject=verified_claims.subject,
            issuer=claims["iss"],
            tenant_id=claims.get("tid"),
            claims=MappingProxyType(
                {name: _freeze_claim_value(value) for name, value in claims.items()}
            ),
        )


@dataclass(frozen=True)
class VerifiedOIDCLoginContext:
    """Non-secret correlation context for downstream OIDC login policy."""

    attempt_id: int
    website_id: int | None

    @classmethod
    def from_attempt(cls, attempt):
        """Build the narrow immutable context from one verified attempt."""
        return cls(
            attempt_id=int(attempt.id),
            website_id=int(attempt.website_id) if attempt.website_id else None,
        )


@dataclass(frozen=True)
class OIDCFailure:
    """A redacted terminal OIDC failure notification."""

    reason: str
    attempt_id: int


class ResUsers(models.Model):
    """Authenticate OIDC only after its matching attempt is fully validated."""

    _inherit = "res.users"

    @api.model
    def auth_oauth(self, provider, params):
        """Keep native OAuth untouched and route OIDC through the strict boundary."""
        oauth_provider = self.env["auth.oauth.provider"].browse(provider).exists()
        if oauth_provider and oauth_provider.flow == "access_token":
            return super().auth_oauth(provider, params)
        if not oauth_provider or oauth_provider.flow != "id_token_code":
            raise AccessDenied()
        attempt = self._claimed_oidc_attempt(
            oauth_provider, params.get("_auth_oidc_attempt_id")
        )
        try:
            if params.get("error"):
                raise OIDCAuthenticationError("provider_denied_authorization")
            access_token, id_token = oauth_provider.exchange_authorization_code(
                attempt, params.get("code")
            )
            verified_claims = oauth_provider.verify_id_token(
                id_token, access_token, attempt
            )
            principal = VerifiedOIDCPrincipal.from_verified_claims(
                oauth_provider.id, verified_claims
            )
            native_params = {
                "access_token": access_token,
                "state": json.dumps(attempt.native_state),
            }
            login_context = VerifiedOIDCLoginContext.from_attempt(attempt)
            login = self._auth_oidc_signin(
                oauth_provider.id, principal, login_context, native_params
            )
            if not login:
                raise OIDCAuthenticationError("native_signin_denied")
            attempt.mark_consumed()
            return self.env.cr.dbname, login, access_token
        except OIDCAuthenticationError as error:
            attempt.mark_failed()
            self._notify_oidc_failure(oauth_provider, error, attempt)
            _logger.info(
                "OIDC authentication failed reason=%s provider_id=%s attempt_id=%s",
                error.reason,
                oauth_provider.id,
                attempt.id,
            )
            raise AccessDenied() from None
        except Exception:
            attempt.mark_failed()
            _logger.exception(
                "Unexpected OIDC authentication failure provider_id=%s attempt_id=%s",
                oauth_provider.id,
                attempt.id,
            )
            raise AccessDenied() from None

    @api.model
    def _claimed_oidc_attempt(self, oauth_provider, attempt_id):
        """Return the claimed current-database attempt for this provider or deny."""
        if not isinstance(attempt_id, int):
            raise AccessDenied()
        attempt = self.env["auth.oidc.login.attempt"].sudo().browse(attempt_id).exists()
        if (
            not attempt
            or attempt.status != "claimed"
            or attempt.provider_id != oauth_provider
            or attempt.database_name != self.env.cr.dbname
            or attempt.expires_at < fields.Datetime.now()
        ):
            raise AccessDenied()
        return attempt

    @api.model
    def _auth_oidc_signin(self, provider, principal, login_context, native_params):
        """Delegate a verified immutable principal to native OAuth user lookup."""
        del login_context
        validation = {"user_id": principal.subject}
        for name in ("email", "name"):
            if isinstance(principal.claims.get(name), str):
                validation[name] = principal.claims[name]
        return self._auth_oauth_signin(provider, validation, native_params)

    @api.model
    def _notify_oidc_failure(self, provider, error, attempt):
        """Notify one expected terminal failure without changing its outcome."""
        failure = OIDCFailure(reason=error.reason, attempt_id=int(attempt.id))
        try:
            with self.env.cr.savepoint():
                self._auth_oidc_failure(provider.id, failure)
        except Exception:
            _logger.error(
                "OIDC failure hook failed provider_id=%s attempt_id=%s",
                provider.id,
                attempt.id,
            )

    @api.model
    def _auth_oidc_failure(self, provider, failure):
        """Receive one redacted expected terminal failure notification."""
        del provider, failure
