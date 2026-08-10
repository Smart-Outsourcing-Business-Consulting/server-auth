# Copyright 2026 Smart Outsourcing Business Consulting
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

from odoo.tests.common import TransactionCase


class TestHrEmployeeView(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.company = cls.env.company
        cls.portal_user = cls._create_user("Portal user", "portal-user")
        cls.internal_user = cls._create_user("Internal user", "internal-user")
        cls.portal_user.groups_id = [(6, 0, [cls.env.ref("base.group_portal").id])]
        cls.internal_user.groups_id = [(6, 0, [cls.env.ref("base.group_user").id])]

    @classmethod
    def _create_user(cls, name, login):
        return (
            cls.env["res.users"]
            .with_context(no_reset_password=True)
            .create(
                {
                    "name": name,
                    "login": login,
                    "company_id": cls.company.id,
                    "company_ids": [(6, 0, [cls.company.id])],
                }
            )
        )

    def test_employee_form_allows_portal_and_internal_users(self):
        arch, _view = self.env["hr.employee"]._get_view(
            self.env.ref("hr.view_employee_form").id, "form"
        )
        user_nodes = arch.xpath(
            "//page[@name='hr_settings']//field[@name='user_id'][@domain]"
        )

        self.assertEqual(len(user_nodes), 1)
        domain = user_nodes[0].get("domain")
        self.assertEqual(domain, "[('company_ids', 'in', company_id)]")

        eligible_users = self.env["res.users"].search(
            [("company_ids", "in", self.company.id)]
        )
        self.assertIn(self.portal_user, eligible_users)
        self.assertIn(self.internal_user, eligible_users)

    def test_linking_portal_user_does_not_change_user_type_or_hr_access(self):
        portal_employee = self.env["hr.employee"].create(
            {"name": "Portal employee", "user_id": self.portal_user.id}
        )
        internal_employee = self.env["hr.employee"].create(
            {"name": "Internal employee", "user_id": self.internal_user.id}
        )

        self.assertEqual(portal_employee.user_id, self.portal_user)
        self.assertEqual(internal_employee.user_id, self.internal_user)
        self.assertTrue(self.portal_user.share)
        self.assertFalse(self.portal_user.has_group("base.group_user"))
        self.assertFalse(
            self.env["hr.employee"]
            .with_user(self.portal_user)
            .check_access_rights("read", raise_exception=False)
        )
