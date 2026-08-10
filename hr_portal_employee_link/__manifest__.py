# Copyright 2026 Smart Outsourcing Business Consulting
# License AGPL-3.0 or later (https://www.gnu.org/licenses/agpl).

{
    "name": "HR Portal Employee Link",
    "summary": "Allow portal users to be selected as an employee's related user",
    "version": "18.0.1.0.0",
    "category": "Human Resources",
    "website": "https://github.com/OCA/server-auth",
    "author": "Smart Outsourcing Business Consulting, Odoo Community Association (OCA)",
    "license": "AGPL-3",
    "installable": True,
    "application": False,
    "development_status": "Beta",
    "depends": ["hr"],
    "data": ["views/hr_employee_views.xml"],
}
