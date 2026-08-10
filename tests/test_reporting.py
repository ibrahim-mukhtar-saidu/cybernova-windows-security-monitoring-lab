import json
import unittest
import tempfile
from datetime import datetime
from pathlib import Path

from reporting.report_generator import (
    make_json_safe,
    html_escape,
    generate_json_report,
    generate_html_report,
)


class TestReporting(unittest.TestCase):

    def setUp(self):
        self.alerts = [
            {
                "rule_name": "Repeated Failed Logons",
                "severity": "HIGH",
                "affected_user": "lab-admin",
                "host": "WIN-DC01",
                "mitre_attack": "T1110 - Brute Force",
                "risk": "HIGH",
                "source_ip": "203.0.113.25",
                "timestamp": datetime(
                    2026, 8, 10, 10, 0, 0
                ),
            },
            {
                "rule_name": "Windows Security Log Cleared",
                "severity": "HIGH",
                "affected_user": "lab-admin",
                "host": "WIN-DC01",
                "mitre_attack": (
                    "T1070.001 - Clear Windows Event Logs"
                ),
                "risk": "HIGH",
            },
        ]

    def test_make_json_safe_datetime(self):
        value = datetime(2026, 8, 10, 10, 0, 0)

        result = make_json_safe(value)

        self.assertEqual(
            result,
            "2026-08-10T10:00:00",
        )

    def test_make_json_safe_nested_data(self):
        value = {
            "timestamp": datetime(
                2026, 8, 10, 10, 0, 0
            ),
            "items": [
                {
                    "timestamp": datetime(
                        2026, 8, 10, 11, 0, 0
                    )
                }
            ],
        }

        result = make_json_safe(value)

        self.assertEqual(
            result["timestamp"],
            "2026-08-10T10:00:00",
        )

        self.assertEqual(
            result["items"][0]["timestamp"],
            "2026-08-10T11:00:00",
        )

    def test_html_escape(self):
        value = '<script>alert("test")</script>'

        result = html_escape(value)

        self.assertNotIn("<script>", result)
        self.assertNotIn("</script>", result)
        self.assertIn("&lt;script&gt;", result)
        self.assertIn("&quot;test&quot;", result)

    def test_generate_json_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = (
                Path(temp_dir)
                / "security_alerts.json"
            )

            result = generate_json_report(
                self.alerts,
                output,
            )

            self.assertEqual(result, output)
            self.assertTrue(output.exists())

            with output.open(
                "r",
                encoding="utf-8",
            ) as file:
                report = json.load(file)

            self.assertEqual(
                report["report_name"],
                "CyberNova Windows Security Monitoring Report",
            )
            self.assertEqual(
                report["total_alerts"],
                2,
            )
            self.assertEqual(
                len(report["alerts"]),
                2,
            )

            self.assertEqual(
                report["alerts"][0]["severity"],
                "HIGH",
            )

            self.assertEqual(
                report["alerts"][0]["timestamp"],
                "2026-08-10T10:00:00",
            )

    def test_generate_html_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = (
                Path(temp_dir)
                / "security_report.html"
            )

            result = generate_html_report(
                self.alerts,
                output,
            )

            self.assertEqual(result, output)
            self.assertTrue(output.exists())

            html = output.read_text(
                encoding="utf-8"
            )

            self.assertIn(
                "CyberNova Windows Security Monitoring Report",
                html,
            )

            self.assertIn(
                "Repeated Failed Logons",
                html,
            )

            self.assertIn(
                "Windows Security Log Cleared",
                html,
            )

            self.assertIn(
                "T1110 - Brute Force",
                html,
            )

            self.assertIn(
                "lab-admin",
                html,
            )

            self.assertIn(
                "WIN-DC01",
                html,
            )

    def test_report_directory_is_created(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = (
                Path(temp_dir)
                / "nested"
                / "reports"
                / "security.json"
            )

            generate_json_report(
                self.alerts,
                output,
            )

            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
