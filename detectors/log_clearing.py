#!/usr/bin/env python3

RULE_NAME = "Windows Security Log Cleared"
SEVERITY = "HIGH"
MITRE_ATTACK = "T1070.001 - Clear Windows Event Logs"


def detect(events):
    """
    Detect Windows Security Event Log clearing.

    Event ID:
        1102 = The audit log was cleared.

    Detection:
        Identify Security log-clearing events and generate
        an investigation alert.

    Note:
        Log clearing may be legitimate administrative activity.
        The event should be correlated with the responsible
        account, host, authorization, and surrounding activity.
    """

    alerts = []

    for event in events:
        if event.get("event_id") != 1102:
            continue

        raw = event.get("raw", {})
        timestamp = event.get("timestamp")

        alerts.append(
            {
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "mitre_attack": MITRE_ATTACK,
                "affected_user": event.get("user"),
                "host": event.get("host"),
                "timestamp": (
                    timestamp.isoformat()
                    if timestamp
                    else None
                ),
                "action": raw.get("ACTION"),
                "risk": "HIGH",
                "related_events": [event],
                "timeline": [
                    {
                        "timestamp": (
                            timestamp.isoformat()
                            if timestamp
                            else None
                        ),
                        "event_id": event.get("event_id"),
                        "user": event.get("user"),
                        "host": event.get("host"),
                        "action": raw.get("ACTION"),
                    }
                ],
                "recommendation": (
                    "Investigate the Security log-clearing activity "
                    "immediately. Verify whether the action was "
                    "authorized, identify the responsible account, "
                    "review activity immediately before the log was "
                    "cleared, and determine whether additional "
                    "evidence may have been removed."
                ),
                "false_positive_note": (
                    "Security logs may be cleared during legitimate "
                    "administrative maintenance, testing, or incident "
                    "response. Validate authorization and correlate "
                    "the event with change-management or operational "
                    "activity before determining maliciousness."
                ),
            }
        )

    return alerts
