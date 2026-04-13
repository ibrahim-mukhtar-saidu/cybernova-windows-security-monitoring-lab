#!/usr/bin/env python3

RULE_NAME = "Account Lockout"
SEVERITY = "MEDIUM"
MITRE_ATTACK = "T1110 - Brute Force"

def detect(events):
    """
    Detect Windows account lockout events.

    Event ID:
        4740 = A user account was locked out.

    Detection:
        Identify account lockouts and generate an
        investigation alert.

    Note:
        Account lockouts can result from legitimate causes,
        such as an expired password, mapped drives, scheduled
        tasks, or repeated incorrect authentication.
    """

    alerts = []

    for event in events:
        if event.get("event_id") != 4740:
            continue

        raw = event.get("raw", {})

        creator = event.get("user")
        target_user = raw.get("TARGET_USER") or event.get("user")
        source_ip = event.get("source_ip")

        timestamp = event.get("timestamp")

        alerts.append(
            {
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "mitre_attack": MITRE_ATTACK,
                "affected_user": target_user,
                "triggered_by": creator,
                "source_ip": source_ip,
                "host": event.get("host"),
                "timestamp": (
                    timestamp.isoformat()
                    if timestamp
                    else None
                ),
                "action": raw.get("ACTION"),
                "risk": "MEDIUM",
                "related_events": [event],
                "timeline": [
                    {
                        "timestamp": (
                            timestamp.isoformat()
                            if timestamp
                            else None
                        ),
                        "event_id": event.get("event_id"),
                        "user": creator,
                        "target_user": target_user,
                        "source_ip": source_ip,
                        "action": raw.get("ACTION"),
                    }
                ],
                "recommendation": (
                    "Investigate the account lockout and determine "
                    "whether it resulted from legitimate activity "
                    "or repeated suspicious authentication attempts. "
                    "Review recent failed logons, identify the source, "
                    "and confirm whether the account owner expected "
                    "the activity."
                ),
                "false_positive_note": (
                    "Account lockouts can be caused by legitimate "
                    "password mistakes, stale credentials, mapped "
                    "drives, scheduled tasks, or service accounts. "
                    "Correlate the lockout with authentication "
                    "events before determining maliciousness."
                ),
            }
        )

    return alerts
