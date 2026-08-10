# Copyright 2026 Smart Outsourcing Business Consulting
# License: AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

"""Private, one-time persistence for OpenID Connect code-flow attempts."""

import base64
import hashlib
import secrets
from datetime import timedelta

from odoo import _, api, fields, models
from odoo.exceptions import AccessDenied


class AuthOIDCLoginAttempt(models.Model):
    """Persist the browser-bound material for one OIDC code-flow login."""

    _name = "auth.oidc.login.attempt"
    _description = "OpenID Connect Login Attempt"
    _order = "id desc"

    provider_id = fields.Many2one(
        "auth.oauth.provider", required=True, index=True, ondelete="cascade"
    )
    database_name = fields.Char(required=True, index=True)
    session_fingerprint = fields.Char(required=True, index=True)
    state_digest = fields.Char(required=True, index=True, copy=False)
    native_state = fields.Json(required=True, copy=False)
    website_id = fields.Integer(copy=False)
    callback_uri = fields.Char(required=True, copy=False)
    nonce = fields.Char(required=True, copy=False)
    code_verifier = fields.Char(required=True, copy=False)
    expires_at = fields.Datetime(required=True, index=True, copy=False)
    status = fields.Selection(
        [
            ("pending", "Pending"),
            ("claimed", "Claimed"),
            ("consumed", "Consumed"),
            ("failed", "Failed"),
        ],
        required=True,
        default="pending",
        index=True,
        copy=False,
    )
    terminal_at = fields.Datetime(index=True, copy=False)

    _sql_constraints = [
        (
            "auth_oidc_login_attempt_state_digest_unique",
            "unique(state_digest)",
            "OIDC login attempt state must be unique.",
        ),
    ]

    @api.model
    def _state_digest(self, state):
        """Return the lookup digest for a browser-visible state value."""
        return hashlib.sha256(state.encode("ascii")).hexdigest()

    @api.model
    def _session_fingerprint(self, session_id):
        """Return a one-way fingerprint for an Odoo browser session ID."""
        if not session_id:
            raise AccessDenied(_("An OIDC browser session is required."))
        return hashlib.sha256(session_id.encode("utf-8")).hexdigest()

    @api.model
    def create_for_authorization(
        self,
        provider,
        database_name,
        session_id,
        native_state,
        website_id,
        callback_uri,
    ):
        """Create one browser-bound attempt and return its public state value."""
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)
        expires_at = fields.Datetime.now() + timedelta(minutes=10)
        attempt = self.sudo().create(
            {
                "provider_id": provider.id,
                "database_name": database_name,
                "session_fingerprint": self._session_fingerprint(session_id),
                "state_digest": self._state_digest(state),
                "native_state": native_state,
                "website_id": website_id,
                "callback_uri": callback_uri,
                "nonce": nonce,
                "code_verifier": code_verifier,
                "expires_at": expires_at,
            }
        )
        return attempt, state

    def code_challenge(self):
        """Return this attempt's RFC 7636 S256 code challenge."""
        self.ensure_one()
        return (
            base64.urlsafe_b64encode(
                hashlib.sha256(self.code_verifier.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode("ascii")
        )

    @api.model
    def claim_from_callback(self, state, database_name, session_id):
        """Atomically claim an unexpired attempt bound to this browser session."""
        if not state or not isinstance(state, str):
            return self.browse()
        try:
            digest = self._state_digest(state)
        except UnicodeEncodeError:
            return self.browse()
        candidate = self.sudo().search([("state_digest", "=", digest)], limit=1)
        if not candidate:
            return candidate

        query = """
            UPDATE auth_oidc_login_attempt
               SET status = 'claimed', write_date = NOW()
             WHERE id = %s
               AND state_digest = %s
               AND status = 'pending'
               AND expires_at >= NOW()
               AND database_name = %s
               AND provider_id = %s
               AND session_fingerprint = %s
         RETURNING id
        """
        self.env.cr.execute(
            query,
            (
                candidate.id,
                digest,
                database_name,
                candidate.provider_id.id,
                self._session_fingerprint(session_id),
            ),
        )
        row = self.env.cr.fetchone()
        if not row:
            return self.browse()
        attempt = self.sudo().browse(row[0])
        attempt.invalidate_recordset(["status"])
        return attempt

    def mark_failed(self):
        """Make a claimed attempt terminal after exchange or validation failure."""
        self.filtered(lambda attempt: attempt.status == "claimed").sudo().write(
            {"status": "failed", "terminal_at": fields.Datetime.now()}
        )

    def mark_consumed(self):
        """Make a claimed attempt terminal after successful native sign-in."""
        self.filtered(lambda attempt: attempt.status == "claimed").sudo().write(
            {"status": "consumed", "terminal_at": fields.Datetime.now()}
        )

    @api.model
    def _cron_cleanup_expired_attempts(self):
        """Delete terminal and expired attempts after the fixed retention window."""
        cutoff = fields.Datetime.now() - timedelta(hours=24)
        stale_attempts = self.sudo().search(
            [
                "|",
                ("expires_at", "<", cutoff),
                "&",
                ("status", "in", ("consumed", "failed")),
                ("terminal_at", "<", cutoff),
            ]
        )
        stale_attempts.unlink()
