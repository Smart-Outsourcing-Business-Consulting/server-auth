# Copyright 2026 Smart Outsourcing Business Consulting
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

from odoo.upgrade import util

BRIDGE_MODULE = "hr_portal_employee_link"
BRIDGE_VIEW = f"{BRIDGE_MODULE}.view_employee_form"


def migrate(cr, version):
    """Remove the obsolete Odoo 18 view bridge without changing HR links."""
    bridge_view_id = util.ref(cr, BRIDGE_VIEW)
    if bridge_view_id:
        cr.execute(
            """
            SELECT view.id,
                   COALESCE(data.module || '.' || data.name, view.name)
              FROM ir_ui_view AS view
         LEFT JOIN ir_model_data AS data
                ON data.model = 'ir.ui.view'
               AND data.res_id = view.id
             WHERE view.inherit_id = %s
            """,
            [bridge_view_id],
        )
        inherited_views = cr.fetchall()
        if inherited_views:
            references = ", ".join(
                f"{reference} ({view_id})" for view_id, reference in inherited_views
            )
            raise util.MigrationError(
                f"Cannot remove {BRIDGE_VIEW}; inherited views remain: {references}"
            )

    cr.execute(
        """
        CREATE TEMPORARY TABLE auth_oidc_hr_employee_user_before
        AS SELECT id, user_id FROM hr_employee
        """
    )
    util.remove_module(cr, BRIDGE_MODULE)

    cr.execute(
        """
        (SELECT id, user_id FROM auth_oidc_hr_employee_user_before
         EXCEPT
         SELECT id, user_id FROM hr_employee)
        UNION ALL
        (SELECT id, user_id FROM hr_employee
         EXCEPT
         SELECT id, user_id FROM auth_oidc_hr_employee_user_before)
        LIMIT 1
        """
    )
    if cr.fetchone():
        raise util.MigrationError(
            "Removing hr_portal_employee_link changed employee-user links."
        )
    cr.execute("DROP TABLE auth_oidc_hr_employee_user_before")

    if util.ref(cr, BRIDGE_VIEW):
        raise util.MigrationError(f"The obsolete view {BRIDGE_VIEW} was not removed.")
