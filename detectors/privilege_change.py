#!/usr/bin/env python3

RULE_NAME = "Privileged Group Membership Change"
SEVERITY = "HIGH"
MITRE_ATTACK = "T1098 - Account Manipulation"


def detect(events):
    """
    Detect changes to privileged Windows group membership.

    Event ID:
        4728 = Member added to a security-enabled global group

    Detection:
        Identify membership changes involving privileged groups.
    """

    privileged_groups = {
        "Administrators",
        "Domain Admins",
        "Enterprise Admins",
        "Backup Operators",
        "Account Operators",
    }

    alerts = []

    for event in events:

        if event.get("event_id") != 4728:
            continue

        raw = event.get("raw", {})

        group = raw.get("GROUP")
        user = event.get("user")
        action = raw.get("ACTION")

        if group not in privileged_groups:
            continue

        alerts.append(
            {
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "mitre_attack": MITRE_ATTACK,
                "affected_user": user,
                "privileged_group": group,
                "action": action,
                "host": event.get("host"),
                "timestamp": event.get(
                    "timestamp"
                ).isoformat(),
                "risk": "HIGH",
                "related_events": [event],
                "timeline": [
                    {
                        "timestamp": event.get(
                            "timestamp"
                        ).isoformat(),
                        "event_id": event.get("event_id"),
                        "user": user,
                        "group": group,
                        "action": action,
                        "host": event.get("host"),
                    }
                ],
                "recommendation": (
                    "Verify that the privileged group membership "
                    "change was authorized. Identify the administrator "
                    "who performed the action, confirm the business "
                    "justification, review the affected account's "
                    "new privileges, and investigate related "
                    "authentication activity."
                ),
            }
        )

    return alerts
