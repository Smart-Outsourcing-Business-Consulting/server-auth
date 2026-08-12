# Copyright 2026 Smart Outsourcing Business Consulting
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

"""Mandatory HR reconciliation at the generic OIDC finalizer boundary."""

from odoo import api, models

from odoo.addons.auth_oidc.models.auth_oauth_provider import OIDCAuthenticationError


class ResUsers(models.Model):
    """Require one mapped employee record before a successful OIDC login."""

    _inherit = "res.users"

    @api.model
    def _auth_oidc_finalize_user_provisioning(
        self, provider, principal, login_context, user
    ):
        """Reconcile exactly one employee in the user's Default Company."""
        super()._auth_oidc_finalize_user_provisioning(
            provider, principal, login_context, user
        )
        claim_value = principal.claims.get("department")
        if not isinstance(claim_value, str):
            raise OIDCAuthenticationError("invalid_department_claim")
        claim_value = claim_value.strip()
        if not claim_value:
            raise OIDCAuthenticationError("invalid_department_claim")

        mapping = (
            self.env["auth.oidc.hr.department.mapping"]
            .sudo()
            .with_context(active_test=False)
            .search(
                [
                    ("provider_id", "=", provider.id),
                    ("claim_value", "=", claim_value),
                    ("company_id", "=", user.company_id.id),
                ]
            )
        )
        if not mapping:
            raise OIDCAuthenticationError("department_mapping_unmapped")
        if len(mapping) != 1:
            raise OIDCAuthenticationError("department_mapping_ambiguous")
        if not mapping.active:
            raise OIDCAuthenticationError("department_mapping_archived")
        department = mapping.department_id
        if (
            not department
            or not department.active
            or department.company_id != user.company_id
        ):
            raise OIDCAuthenticationError("department_mapping_invalid")

        employee_model = self.env["hr.employee"].sudo().with_context(active_test=False)
        employee = employee_model.search(
            [("user_id", "=", user.id), ("company_id", "=", user.company_id.id)]
        )
        if len(employee) > 1:
            raise OIDCAuthenticationError("employee_mapping_ambiguous")
        if employee and not employee.active:
            raise OIDCAuthenticationError("employee_mapping_archived")
        if employee:
            employee.write({"department_id": department.id})
            return
        employee_model.create(
            {
                "name": user.name,
                "user_id": user.id,
                "company_id": user.company_id.id,
                "department_id": department.id,
            }
        )
