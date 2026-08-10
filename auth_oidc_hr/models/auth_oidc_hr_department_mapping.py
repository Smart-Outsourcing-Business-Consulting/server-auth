# Copyright 2026 Smart Outsourcing Business Consulting
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

"""Administrator-owned exact OIDC department claim mappings."""

from odoo import api, fields, models
from odoo.exceptions import ValidationError


class AuthOIDCHRDepartmentMapping(models.Model):
    """Map one provider claim value and company to one active department."""

    _name = "auth.oidc.hr.department.mapping"
    _description = "OIDC HR Department Mapping"
    _order = "provider_id, company_id, claim_value, id"

    active = fields.Boolean(default=True)
    provider_id = fields.Many2one(
        "auth.oauth.provider", required=True, ondelete="cascade", index=True
    )
    claim_value = fields.Char(required=True, index=True)
    company_id = fields.Many2one("res.company", required=True, index=True)
    department_id = fields.Many2one(
        "hr.department", required=True, ondelete="restrict", index=True
    )

    _sql_constraints = [
        (
            "provider_value_company_unique",
            "unique(provider_id, claim_value, company_id)",
            "An OIDC provider claim value can be mapped only once per company.",
        )
    ]

    @api.model_create_multi
    def create(self, vals_list):
        """Store the one exact stripped administrator-provided claim value."""
        return super().create([self._normalize_claim_value(vals) for vals in vals_list])

    def write(self, vals):
        """Keep an edited claim value in the same normalized representation."""
        return super().write(self._normalize_claim_value(vals))

    @staticmethod
    def _normalize_claim_value(vals):
        vals = dict(vals)
        claim_value = vals.get("claim_value")
        if isinstance(claim_value, str):
            vals["claim_value"] = claim_value.strip()
        return vals

    @api.constrains("claim_value", "company_id", "department_id")
    def _check_exact_active_department(self):
        """Reject values that cannot be resolved safely at OIDC login time."""
        for mapping in self:
            if not mapping.claim_value:
                raise ValidationError("The OIDC department claim value is required.")
            if (
                not mapping.department_id.active
                or mapping.department_id.company_id != mapping.company_id
            ):
                raise ValidationError(
                    "The mapped department must be active and belong to the "
                    "mapping company."
                )
