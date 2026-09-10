#!/usr/bin/env python3

from detectors.failed_logon import detect as detect_failed_logon
from detectors.login_after_failures import detect as detect_login_after_failures
from detectors.user_creation import detect as detect_user_creation
from detectors.privilege_change import detect as detect_privilege_change
from detectors.powershell_execution import detect as detect_powershell
from detectors.process_execution import detect as detect_process_execution
from detectors.account_lockout import detect as detect_account_lockout
from detectors.log_clearing import detect as detect_log_clearing


DETECTORS = [
    ("Repeated Failed Logons", detect_failed_logon),
    (
        "Successful Login After Multiple Failures",
        detect_login_after_failures,
    ),
    ("New User Account Creation", detect_user_creation),
    ("Privileged Group Membership Change", detect_privilege_change),
    ("Suspicious PowerShell Execution", detect_powershell),
    ("Suspicious Process Execution", detect_process_execution),
    ("Account Lockout", detect_account_lockout),
    ("Windows Security Log Cleared", detect_log_clearing),
]


def run_detections(events):
    """
    Run all CyberNova Windows detection rules.

    Returns a unified list of security alerts.
    """

    alerts = []

    for detector_name, detector in DETECTORS:
        try:
            detector_alerts = detector(events)

            for alert in detector_alerts:
                alert["detector"] = detector_name
                alerts.append(alert)

        except Exception as exc:
            raise RuntimeError(
                f"Detector failed: {detector_name}"
            ) from exc

    return alerts


def summarize_alerts(alerts):
    """
    Generate a high-level summary of detection results.
    """

    summary = {
        "total_alerts": len(alerts),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for alert in alerts:
        severity = str(
            alert.get("severity", "LOW")
        ).lower()

        if severity in summary:
            summary[severity] += 1

    return summary
