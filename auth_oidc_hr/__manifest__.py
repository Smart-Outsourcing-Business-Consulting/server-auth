# Copyright 2026 Smart Outsourcing Business Consulting
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

{
    "name": "OpenID Connect HR Reconciliation",
    "summary": "Reconcile OIDC users with their mapped HR department",
    "version": "18.0.1.0.0",
    "category": "Authentication",
    "website": "https://github.com/OCA/server-auth",
    "author": "Smart Outsourcing Business Consulting, Odoo Community Association (OCA)",
    "license": "AGPL-3",
    "installable": True,
    "application": False,
    "development_status": "Beta",
    "depends": ["auth_oidc", "hr", "hr_portal_employee_link"],
    "data": [
        "security/ir.model.access.csv",
        "views/auth_oidc_hr_department_mapping_views.xml",
    ],
}
