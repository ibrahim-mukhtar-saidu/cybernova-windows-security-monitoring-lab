import unittest
import tempfile
from datetime import datetime
from pathlib import Path

from dashboards.dashboard_generator import (
    html_escape,
    generate_dashboard,
)


class TestDashboardGenerator(unittest.TestCase):

    def setUp(self):
        self.alerts = [
            {
                "rule_name": "Repeated Failed Logons",
                "severity": "HIGH",
                "affected_user": "lab-admin",
                "host": "WIN-DC01",
                "source_ip": "203.0.113.25",
                "mitre_attack": "T1110 - Brute Force",
                "detector": "Repeated Failed Logons",
                "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            },
            {
                "rule_name": "Successful Login After Multiple Failures",
                "severity": "CRITICAL",
                "affected_user": "lab-admin",
                "host": "WIN-DC01",
                "source_ip": "203.0.113.25",
                "mitre_attack": "T1078 - Valid Accounts",
                "detector": "Successful Login After Multiple Failures",
                "timestamp": datetime(2026, 8, 10, 10, 5, 0),
            },
            {
                "rule_name": "Suspicious Process Execution",
                "severity": "MEDIUM",
                "affected_user": "lab-user",
                "host": "WIN-WS01",
                "source_ip": "-",
                "mitre_attack": "T1059 - Command and Scripting Interpreter",
                "detector": "Suspicious Process Execution",
                "timestamp": datetime(2026, 8, 10, 10, 10, 0),
            },
        ]

    def test_html_escape(self):
        value = '<script>alert("test")</script>'

        escaped = html_escape(value)

        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)
        self.assertIn("&quot;test&quot;", escaped)

    def test_dashboard_file_created(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "dashboard.html"

            result = generate_dashboard(
                self.alerts,
                output,
            )

            self.assertEqual(result, output)
            self.assertTrue(output.exists())
            self.assertGreater(output.stat().st_size, 0)

    def test_dashboard_contains_title(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "dashboard.html"

            generate_dashboard(
                self.alerts,
                output,
            )

            content = output.read_text(
                encoding="utf-8"
            )

            self.assertIn(
                "CYBERNOVA SOC DASHBOARD",
                content,
            )

    def test_dashboard_contains_alert_counts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "dashboard.html"

            generate_dashboard(
                self.alerts,
                output,
            )

            content = output.read_text(
                encoding="utf-8"
            )

            self.assertIn("TOTAL ALERTS", content)
            self.assertIn("3", content)
            self.assertIn("CRITICAL", content)
            self.assertIn("HIGH", content)
            self.assertIn("MEDIUM", content)

    def test_dashboard_contains_detection_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "dashboard.html"

            generate_dashboard(
                self.alerts,
                output,
            )

            content = output.read_text(
                encoding="utf-8"
            )

            self.assertIn(
                "Repeated Failed Logons",
                content,
            )

            self.assertIn(
                "Successful Login After Multiple Failures",
                content,
            )

            self.assertIn(
                "Suspicious Process Execution",
                content,
            )

    def test_dashboard_contains_alert_details(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "dashboard.html"

            generate_dashboard(
                self.alerts,
                output,
            )

            content = output.read_text(
                encoding="utf-8"
            )

            self.assertIn("lab-admin", content)
            self.assertIn("WIN-DC01", content)
            self.assertIn("203.0.113.25", content)
            self.assertIn("T1110 - Brute Force", content)

    def test_dashboard_escapes_alert_data(self):
        malicious_alerts = [
            {
                "rule_name": "<script>alert('x')</script>",
                "severity": "HIGH",
                "affected_user": "<admin>",
                "host": "WIN-DC01",
                "source_ip": "203.0.113.25",
                "mitre_attack": "T1110",
                "detector": "Test Detector",
            }
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "dashboard.html"

            generate_dashboard(
                malicious_alerts,
                output,
            )

            content = output.read_text(
                encoding="utf-8"
            )

            self.assertNotIn(
                "<script>alert('x')</script>",
                content,
            )

            self.assertIn(
                "&lt;script&gt;",
                content,
            )

            self.assertIn(
                "&lt;admin&gt;",
                content,
            )


if __name__ == "__main__":
    unittest.main()
