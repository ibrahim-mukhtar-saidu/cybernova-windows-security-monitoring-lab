#!/usr/bin/env python3

RULE_NAME = "Suspicious PowerShell Execution"
SEVERITY = "HIGH"
MITRE_ATTACK = "T1059.001 - PowerShell"

SUSPICIOUS_PATTERNS = [
    "invoke-webrequest",
    "downloadstring",
    "encodedcommand",
    "frombase64string",
    "iex ",
    "invoke-expression",
]


def detect(events):
    """
    Detect potentially suspicious PowerShell execution.

    Event ID:
        4104 = PowerShell Script Block Logging

    Detection:
        Identify PowerShell events containing suspicious
        command patterns.

    Note:
        PowerShell is legitimate administrative software.
        A match indicates activity requiring investigation,
        not confirmed malicious behavior.
    """

    alerts = []

    for event in events:
        if event.get("event_id") != 4104:
            continue

        raw = event.get("raw", {})
        process = str(event.get("process") or "").lower()
        command = str(raw.get("COMMAND") or "")
        command_lower = command.lower()

        if "powershell" not in process:
            continue

        matches = [
            pattern
            for pattern in SUSPICIOUS_PATTERNS
            if pattern in command_lower
        ]

        if not matches:
            continue

        alerts.append(
            {
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "mitre_attack": MITRE_ATTACK,
                "affected_user": event.get("user"),
                "host": event.get("host"),
                "timestamp": event.get("timestamp").isoformat(),
                "process": event.get("process"),
                "command": command,
                "matched_patterns": matches,
                "risk": "HIGH",
                "related_events": [event],
                "timeline": [
                    {
                        "timestamp": event.get("timestamp").isoformat(),
                        "event_id": event.get("event_id"),
                        "user": event.get("user"),
                        "host": event.get("host"),
                        "process": event.get("process"),
                        "command": command,
                    }
                ],
                "false_positive_note": (
                    "PowerShell is commonly used for legitimate "
                    "administration and automation. Validate the "
                    "command, user, host, and expected administrative "
                    "activity before determining maliciousness."
                ),
                "recommendation": (
                    "Review the PowerShell command, confirm whether "
                    "the activity was authorized, identify the user "
                    "and host involved, and correlate with nearby "
                    "authentication and privilege-change events."
                ),
            }
        )

    return alerts
