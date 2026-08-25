# Copyright 2026 Smart Outsourcing Business Consulting
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

from types import MappingProxyType
from unittest.mock import patch

import responses
from psycopg2 import IntegrityError

from odoo.exceptions import AccessError, ValidationError
from odoo.tests.common import TransactionCase, mute_logger

from odoo.addons.auth_oidc.controllers.main import OpenIDController
from odoo.addons.auth_oidc.models.auth_oauth_provider import OIDCAuthenticationError
from odoo.addons.auth_oidc.models.res_users import (
    VerifiedOIDCLoginContext,
    VerifiedOIDCPrincipal,
)
from odoo.addons.auth_oidc.tests.test_auth_oidc_auth_code import (
    MockRequest,
    TestAuthOIDCAuthorizationCodeFlow,
)


class TestAuthOIDCHR(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.company = cls.env.company
        cls.other_company = cls.env["res.company"].create({"name": "Other Company"})
        cls.provider = cls.env["auth.oauth.provider"].create(
            {
                "name": "OIDC HR Provider",
                "client_id": "oidc-hr-provider",
                "auth_endpoint": "https://issuer.example.test/authorize",
                "body": "Sign in",
            }
        )
        cls.department = cls.env["hr.department"].create(
            {"name": "Operations", "company_id": cls.company.id}
        )
        cls.mapping = cls.env["auth.oidc.hr.department.mapping"].create(
            {
                "provider_id": cls.provider.id,
                "claim_value": "Operations",
                "company_id": cls.company.id,
                "department_id": cls.department.id,
            }
        )

    @classmethod
    def _create_user(cls, name, login, group_xmlid, company=None, companies=None):
        company = company or cls.company
        companies = companies or company
        return (
            cls.env["res.users"]
            .with_context(no_reset_password=True)
            .create(
                {
                    "name": name,
                    "login": login,
                    "email": f"{login}@example.test",
                    "company_id": company.id,
                    "company_ids": [(6, 0, [record.id for record in companies])],
                    "group_ids": [(6, 0, [cls.env.ref(group_xmlid).id])],
                }
            )
        )

    @classmethod
    def _principal(cls, department=" Operations "):
        return VerifiedOIDCPrincipal(
            provider_id=cls.provider.id,
            subject="oidc-hr-subject",
            issuer="https://issuer.example.test",
            tenant_id=None,
            claims=MappingProxyType({"department": department}),
        )

    def _finalize(self, user, department=" Operations "):
        return self.env["res.users"]._auth_oidc_finalize_user_provisioning(
            self.provider,
            self._principal(department),
            VerifiedOIDCLoginContext(1, None),
            user,
        )

    def test_mapping_requires_one_active_same_company_department(self):
        self.assertEqual(self.mapping.claim_value, "Operations")
        self.mapping.write({"claim_value": " Finance "})
        self.assertEqual(self.mapping.claim_value, "Finance")
        self.mapping.write({"claim_value": "Operations"})

        with self.assertRaises(ValidationError):
            self.mapping.create(
                {
                    "provider_id": self.provider.id,
                    "claim_value": "",
                    "company_id": self.company.id,
                    "department_id": self.department.id,
                }
            )
        with (
            mute_logger("odoo.sql_db"),
            self.assertRaises(IntegrityError),
            self.env.cr.savepoint(),
        ):
            self.mapping.create(
                {
                    "provider_id": self.provider.id,
                    "claim_value": "Operations",
                    "company_id": self.company.id,
                    "department_id": self.department.id,
                }
            )
        with self.assertRaises(ValidationError):
            self.mapping.create(
                {
                    "provider_id": self.provider.id,
                    "claim_value": "Wrong company",
                    "company_id": self.other_company.id,
                    "department_id": self.department.id,
                }
            )

    def test_internal_and_portal_users_create_or_reuse_one_employee(self):
        for group_xmlid, login in (
            ("base.group_user", "internal-oidc-hr"),
            ("base.group_portal", "portal-oidc-hr"),
        ):
            user = self._create_user(login, login, group_xmlid)
            self._finalize(user)
            employee = (
                self.env["hr.employee"]
                .with_context(active_test=False)
                .search(
                    [("user_id", "=", user.id), ("company_id", "=", self.company.id)]
                )
            )
            self.assertEqual(len(employee), 1)
            self.assertEqual(employee.department_id, self.department)
            self._finalize(user)
            self.assertEqual(
                self.env["hr.employee"]
                .with_context(active_test=False)
                .search_count(
                    [("user_id", "=", user.id), ("company_id", "=", self.company.id)]
                ),
                1,
            )

    def test_internal_and_portal_reuse_update_department_idempotently(self):
        old_department = self.env["hr.department"].create(
            {"name": "Old department", "company_id": self.company.id}
        )
        for group_xmlid, login in (
            ("base.group_user", "internal-existing-employee"),
            ("base.group_portal", "portal-existing-employee"),
        ):
            user = self._create_user(login, login, group_xmlid)
            employee = self.env["hr.employee"].create(
                {
                    "name": user.name,
                    "user_id": user.id,
                    "company_id": self.company.id,
                    "department_id": old_department.id,
                }
            )
            self._finalize(user)
            self.assertEqual(employee.department_id, self.department)
            self._finalize(user)
            self.assertEqual(
                self.env["hr.employee"]
                .with_context(active_test=False)
                .search_count(
                    [("user_id", "=", user.id), ("company_id", "=", self.company.id)]
                ),
                1,
            )

    def test_department_reconciliation_seam_maps_and_updates_one_employee(self):
        user = self._create_user(
            "Neutral seam user", "neutral-seam-user", "base.group_portal"
        )
        users = self.env["res.users"]
        users._auth_oidc_hr_reconcile_department(self.provider, user, " Operations ")
        employee = self.env["hr.employee"].search(
            [("user_id", "=", user.id), ("company_id", "=", self.company.id)]
        )
        self.assertEqual(len(employee), 1)
        self.assertEqual(employee.department_id, self.department)

        finance_department = self.env["hr.department"].create(
            {"name": "Finance", "company_id": self.company.id}
        )
        self.env["auth.oidc.hr.department.mapping"].create(
            {
                "provider_id": self.provider.id,
                "claim_value": "Finance",
                "company_id": self.company.id,
                "department_id": finance_department.id,
            }
        )
        users._auth_oidc_hr_reconcile_department(self.provider, user, "Finance")
        self.assertEqual(len(employee), 1)
        self.assertEqual(employee.department_id, finance_department)

    def test_internal_and_portal_archived_employee_deny_without_replacement(self):
        for group_xmlid, login in (
            ("base.group_user", "internal-archived-employee"),
            ("base.group_portal", "portal-archived-employee"),
        ):
            user = self._create_user(login, login, group_xmlid)
            employee = self.env["hr.employee"].create(
                {
                    "name": user.name,
                    "user_id": user.id,
                    "company_id": self.company.id,
                    "department_id": self.department.id,
                }
            )
            employee.active = False
            with self.assertRaises(OIDCAuthenticationError):
                self._finalize(user)
            employee.invalidate_recordset(["active"])
            self.assertFalse(employee.active)
            self.assertEqual(
                self.env["hr.employee"]
                .with_context(active_test=False)
                .search_count(
                    [("user_id", "=", user.id), ("company_id", "=", self.company.id)]
                ),
                1,
            )

    def test_invalid_claim_or_mapping_deny(self):
        user = self._create_user(
            "Invalid claim user", "invalid-claim-user", "base.group_portal"
        )
        for department in (None, "", [], "Unmapped"):
            with self.assertRaises(OIDCAuthenticationError):
                self._finalize(user, department)

        self.department.active = False
        with self.assertRaises(OIDCAuthenticationError):
            self._finalize(user)

    def test_default_company_is_the_only_employee_company(self):
        for group_xmlid, login in (
            ("base.group_user", "internal-multi-company-user"),
            ("base.group_portal", "portal-multi-company-user"),
        ):
            user = self._create_user(
                "Multi company user",
                login,
                group_xmlid,
                companies=self.company | self.other_company,
            )
            self._finalize(user)
            employees = (
                self.env["hr.employee"]
                .with_context(active_test=False)
                .search([("user_id", "=", user.id)])
            )
            self.assertEqual(employees.company_id, self.company)
            self.assertEqual(user.company_ids, self.company | self.other_company)

    def test_archived_mapping_denies_before_employee_creation(self):
        user = self._create_user(
            "Archived mapping user", "archived-mapping-user", "base.group_portal"
        )
        self.mapping.active = False
        with self.assertRaises(OIDCAuthenticationError):
            self._finalize(user)
        self.assertFalse(
            self.env["hr.employee"]
            .with_context(active_test=False)
            .search([("user_id", "=", user.id), ("company_id", "=", self.company.id)])
        )

    def test_same_name_and_email_unlinked_employee_is_never_claimed(self):
        user = self._create_user(
            "Shared identity", "shared-identity", "base.group_portal"
        )
        unlinked = self.env["hr.employee"].create(
            {"name": user.name, "work_email": user.email, "company_id": self.company.id}
        )
        self._finalize(user)
        linked = self.env["hr.employee"].search([("user_id", "=", user.id)])
        self.assertEqual(len(linked), 1)
        self.assertNotEqual(linked, unlinked)
        self.assertFalse(unlinked.user_id)

    def test_portal_link_does_not_grant_hr_private_access(self):
        user = self._create_user("Portal user", "portal-private", "base.group_portal")
        self._finalize(user)
        self.assertTrue(user.share)
        self.assertFalse(user.has_group("base.group_user"))
        with self.assertRaises(AccessError):
            (self.env["hr.employee"].with_user(user).check_access("read"))

    def test_database_employee_constraint_rejects_an_exact_duplicate(self):
        user = self._create_user(
            "Duplicate employee", "duplicate-employee", "base.group_user"
        )
        self._finalize(user)
        with (
            mute_logger("odoo.sql_db"),
            self.assertRaises(IntegrityError),
            self.env.cr.savepoint(),
        ):
            self.env["hr.employee"].create(
                {"name": user.name, "user_id": user.id, "company_id": self.company.id}
            )


class TestAuthOIDCHRAdapter(TransactionCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.rsa_key_pem, _, cls.rsa_key_public_jwk = (
            TestAuthOIDCAuthorizationCodeFlow._generate_key()
        )

    def setUp(self):
        super().setUp()
        self.provider = self.env["auth.oauth.provider"].create(
            {
                "name": "Adapter OIDC HR Provider",
                "client_id": "auth_oidc-test",
                "auth_endpoint": "http://localhost:8080/authorize",
                "body": "Sign in",
                "flow": "id_token_code",
                "token_endpoint": "http://localhost:8080/auth/realms/master/protocol/openid-connect/token",
                "jwks_uri": "http://localhost:8080/auth/realms/master/protocol/openid-connect/certs",
                "issuer": "http://localhost:8080/auth/realms/master",
                "enabled": True,
            }
        )
        self.provider_rec = self.provider
        self.user = (
            self.env["res.users"]
            .with_context(no_reset_password=True)
            .create(
                {
                    "name": "Adapter OIDC HR User",
                    "login": "adapter-oidc-hr-user",
                    "company_id": self.env.company.id,
                    "company_ids": [(6, 0, [self.env.company.id])],
                    "group_ids": [(6, 0, [self.env.ref("base.group_user").id])],
                    "oauth_provider_id": self.provider.id,
                    "oauth_uid": "test-subject",
                }
            )
        )
        self.department = self.env["hr.department"].create(
            {"name": "Adapter department", "company_id": self.user.company_id.id}
        )
        self.env["auth.oidc.hr.department.mapping"].create(
            {
                "provider_id": self.provider.id,
                "claim_value": "Adapter department",
                "company_id": self.user.company_id.id,
                "department_id": self.department.id,
            }
        )

    @responses.activate
    def test_adapter_finalizes_employee_before_consuming_attempt(self):
        attempt, state = self.env["auth.oidc.login.attempt"]._create_for_authorization(
            self.provider,
            self.env.cr.dbname,
            "auth-oidc-hr-session",
            {"d": self.env.cr.dbname, "p": self.provider.id, "r": "/odoo"},
            False,
            "http://localhost:8069/auth_oauth/signin",
        )
        helper = TestAuthOIDCAuthorizationCodeFlow
        helper._prepare_login_test_responses(
            self,
            attempt,
            claims={"department": " Adapter department "},
        )
        claimed = self.env["auth.oidc.login.attempt"].claim_from_callback(
            state, self.env.cr.dbname, "auth-oidc-hr-session"
        )
        self.env["res.users"].auth_oauth(
            self.provider.id,
            {"_auth_oidc_attempt_id": claimed.id, "code": "code-sentinel"},
        )
        employee = self.env["hr.employee"].search(
            [
                ("user_id", "=", self.user.id),
                ("company_id", "=", self.user.company_id.id),
            ]
        )
        self.assertEqual(employee.department_id, self.department)
        self.assertEqual(claimed.status, "consumed")

    @responses.activate
    def test_adapter_source_hook_skips_jwt_department_reconciliation(self):
        self.env["auth.oidc.hr.department.mapping"].search(
            [("provider_id", "=", self.provider.id)]
        ).unlink()
        attempt, state = self.env["auth.oidc.login.attempt"]._create_for_authorization(
            self.provider,
            self.env.cr.dbname,
            "auth-oidc-hr-scim-session",
            {"d": self.env.cr.dbname, "p": self.provider.id, "r": "/odoo"},
            False,
            "http://localhost:8069/auth_oauth/signin",
        )
        TestAuthOIDCAuthorizationCodeFlow._prepare_login_test_responses(
            self,
            attempt,
            claims={"department": "Unmapped"},
        )
        claimed = self.env["auth.oidc.login.attempt"].claim_from_callback(
            state, self.env.cr.dbname, "auth-oidc-hr-scim-session"
        )
        with patch.object(
            type(self.env["res.users"]),
            "_auth_oidc_hr_should_reconcile_jwt_department",
            return_value=False,
        ):
            self.env["res.users"].auth_oauth(
                self.provider.id,
                {"_auth_oidc_attempt_id": claimed.id, "code": "code-sentinel"},
            )
        self.assertFalse(
            self.env["hr.employee"].search(
                [
                    ("user_id", "=", self.user.id),
                    ("company_id", "=", self.user.company_id.id),
                ]
            )
        )
        self.assertEqual(claimed.status, "consumed")

    @responses.activate
    def test_adapter_rolls_back_credentials_when_department_mapping_is_missing(self):
        self.env["auth.oidc.hr.department.mapping"].search(
            [("provider_id", "=", self.provider.id)]
        ).unlink()
        self.user.sudo().oauth_access_token = "previous-token"
        attempt, state = self.env["auth.oidc.login.attempt"]._create_for_authorization(
            self.provider,
            self.env.cr.dbname,
            "auth-oidc-test-session",
            {"d": self.env.cr.dbname, "p": self.provider.id, "r": "/odoo"},
            False,
            "http://localhost:8069/auth_oauth/signin",
        )
        TestAuthOIDCAuthorizationCodeFlow._prepare_login_test_responses(
            self,
            attempt,
            claims={"department": "Adapter department"},
            access_token="new-token",
        )
        with MockRequest(self.env) as mock_request:
            response = OpenIDController.signin.original_endpoint(
                OpenIDController(), state=state, code="code-sentinel"
            )
            self.assertTrue(mock_request.session["auth_oidc_error"])
        self.user.sudo().invalidate_recordset(["oauth_access_token"])
        attempt.invalidate_recordset(["status"])
        self.assertEqual(self.user.sudo().oauth_access_token, "previous-token")
        self.assertEqual(attempt.status, "failed")
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.location, "/web/login")
