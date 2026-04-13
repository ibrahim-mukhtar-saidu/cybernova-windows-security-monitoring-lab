import unittest

from parser.windows_event_parser import load_events
from engine.detection_engine import run_detections, summarize_alerts


class TestWindowsSecurityMonitoring(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.events = load_events(
            "samples/windows_security_events.log"
        )

    def test_event_count(self):
        self.assertEqual(len(self.events), 10)

    def test_detection_engine_generates_alerts(self):
        alerts = run_detections(self.events)

        self.assertEqual(len(alerts), 8)

    def test_severity_summary(self):
        alerts = run_detections(self.events)
        summary = summarize_alerts(alerts)

        self.assertEqual(summary["total_alerts"], 8)
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["high"], 5)
        self.assertEqual(summary["medium"], 2)
        self.assertEqual(summary["low"], 0)

    def test_failed_logon_alert_exists(self):
        alerts = run_detections(self.events)

        matches = [
            alert for alert in alerts
            if alert["rule_name"] == "Repeated Failed Logons"
        ]

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "HIGH")
        self.assertEqual(matches[0]["affected_user"], "lab-admin")

    def test_successful_login_after_failures(self):
        alerts = run_detections(self.events)

        matches = [
            alert for alert in alerts
            if alert["rule_name"]
            == "Successful Login After Multiple Failures"
        ]

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "CRITICAL")

    def test_user_creation_detection(self):
        alerts = run_detections(self.events)

        matches = [
            alert for alert in alerts
            if alert["rule_name"]
            == "New User Account Creation"
        ]

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["affected_user"], "backup-admin")

    def test_privilege_change_detection(self):
        alerts = run_detections(self.events)

        matches = [
            alert for alert in alerts
            if alert["rule_name"]
            == "Privileged Group Membership Change"
        ]

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "HIGH")

    def test_powershell_detection(self):
        alerts = run_detections(self.events)

        matches = [
            alert for alert in alerts
            if alert["rule_name"]
            == "Suspicious PowerShell Execution"
        ]

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "HIGH")

    def test_process_execution_detection(self):
        alerts = run_detections(self.events)

        matches = [
            alert for alert in alerts
            if alert["rule_name"]
            == "Suspicious Process Execution"
        ]

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "MEDIUM")

    def test_account_lockout_detection(self):
        alerts = run_detections(self.events)

        matches = [
            alert for alert in alerts
            if alert["rule_name"] == "Account Lockout"
        ]

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["affected_user"], "backup-admin")

    def test_log_clearing_detection(self):
        alerts = run_detections(self.events)

        matches = [
            alert for alert in alerts
            if alert["rule_name"]
            == "Windows Security Log Cleared"
        ]

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
