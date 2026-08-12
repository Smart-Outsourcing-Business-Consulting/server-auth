================================
OpenID Connect HR Reconciliation
================================

This Odoo 19 addon makes employee reconciliation a mandatory part of the
``auth_oidc`` provisioning finalizer. Administrators configure an exact mapping
from an OAuth provider, a stripped ``department`` claim value, and a company to
one active department in that company.

On successful OIDC authentication, the addon uses only the user's Default
Company and exact ``(user_id, company_id)`` employee identity. It creates an
absent employee, updates the mapped department on one active employee, and
rejects archived or ambiguous records. It never claims an employee by name or
email, changes user company access, or grants HR access to portal users.

Install this addon only when every successful OIDC login must satisfy this HR
invariant. Without it, ``auth_oidc`` remains independent of HR.

Odoo 19's employee form already permits portal-user links. During upgrade,
this addon removes the obsolete Odoo 18 ``hr_portal_employee_link`` bridge
after checking that no view still inherits from it, and verifies that the
removal did not change any employee/user link.
