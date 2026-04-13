#!/usr/bin/env python3

RULE_NAME = "New User Account Creation"
SEVERITY = "HIGH"
MITRE_ATTACK = "T1136 - Create Account"


def detect(events):
    """
    Detect creation of a new Windows user account.

    Event ID:
        4720 = User account created

    Detection:
        Identify account-creation events and generate an
        investigation alert containing the creator and
        newly created account.
    """

    alerts = []

    for event in events:

        if event.get("event_id") != 4720:
            continue

        creator = event.get("user")
        target_user = event.get("raw", {}).get("TARGET_USER")

        alerts.append(
            {
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "mitre_attack": MITRE_ATTACK,
                "affected_user": target_user,
                "created_by": creator,
                "host": event.get("host"),
                "timestamp": event.get("timestamp").isoformat(),
                "action": event.get("raw", {}).get("ACTION"),
                "risk": "HIGH",
                "related_events": [event],
                "timeline": [
                    {
                        "timestamp": event.get(
                            "timestamp"
                        ).isoformat(),
                        "event_id": event.get("event_id"),
                        "user": creator,
                        "target_user": target_user,
                        "host": event.get("host"),
                        "action": event.get("raw", {}).get(
                            "ACTION"
                        ),
                    }
                ],
                "recommendation": (
                    "Verify that the account creation was authorized. "
                    "Confirm the business purpose of the new account, "
                    "review its assigned privileges, identify who "
                    "performed the action, and investigate related "
                    "authentication or privilege-change activity."
                ),
            }
        )

    return alerts
