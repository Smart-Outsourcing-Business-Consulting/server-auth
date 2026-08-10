This is an Odoo 18-only compatibility addon. The downstream lifecycle addon
must remove it during the Odoo 19 upgrade after confirming that no custom view
inherits `hr_portal_employee_link.view_employee_form`; removing the addon must
not change existing employee-user links. The bridge is unnecessary in Odoo 19,
where the standard employee form already permits portal users in the Related
User picker.
