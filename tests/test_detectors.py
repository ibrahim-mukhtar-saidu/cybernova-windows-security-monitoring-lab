import unittest

from parser.windows_event_parser import load_events
from detectors.failed_logon import detect


class TestFailedLogonDetector(unittest.TestCase):

    def test_repeated_failed_logons_detected(self):
        events = load_events(
            "samples/windows_security_events.log"
        )

        alerts = detect(events)

        self.assertEqual(len(alerts), 1)

        alert = alerts[0]

        self.assertEqual(
            alert["rule_name"],
            "Repeated Failed Logons"
        )

        self.assertEqual(
            alert["severity"],
            "HIGH"
        )

        self.assertEqual(
            alert["mitre_attack"],
            "T1110 - Brute Force"
        )

        self.assertEqual(
            alert["affected_user"],
            "lab-admin"
        )

        self.assertEqual(
            alert["source_ip"],
            "203.0.113.25"
        )

        self.assertEqual(
            alert["count"],
            3
        )

    def test_no_alert_below_threshold(self):
        events = load_events(
            "samples/windows_security_events.log"
        )

        alerts = detect(events, threshold=4)

        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
