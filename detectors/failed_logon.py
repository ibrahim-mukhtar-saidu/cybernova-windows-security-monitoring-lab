#!/usr/bin/env python3

from collections import defaultdict

RULE_NAME = "Repeated Failed Logons"
SEVERITY = "HIGH"
MITRE_ATTACK = "T1110 - Brute Force"


def detect(events, threshold=3):
    """
    Detect repeated Windows failed logon attempts.

    Event ID:
        4625

    Detection:
        Three or more failed logons from the same user
        and source IP.
    """

    grouped = defaultdict(list)

    for event in events:
        if event.get("event_id") != 4625:
            continue

        key = (
            event.get("user"),
            event.get("source_ip"),
        )

        grouped[key].append(event)

    alerts = []

    for (user, source_ip), matches in grouped.items():
        if len(matches) < threshold:
            continue

        matches.sort(key=lambda event: event.get("timestamp"))

        timeline = []

        for event in matches:
            timeline.append(
                {
                    "timestamp": event.get("timestamp").isoformat(),
                    "event_id": event.get("event_id"),
                    "user": event.get("user"),
                    "source_ip": event.get("source_ip"),
                    "status": event.get("status"),
                }
            )

        alerts.append(
            {
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "mitre_attack": MITRE_ATTACK,
                "affected_user": user,
                "source_ip": source_ip,
                "host": matches[0].get("host"),
                "count": len(matches),
                "first_seen": matches[0].get("timestamp").isoformat(),
                "last_seen": matches[-1].get("timestamp").isoformat(),
                "related_events": matches,
                "timeline": timeline,
                "risk": "HIGH",
                "recommendation": (
                    "Investigate whether a successful logon occurred "
                    "after repeated failures, validate the source IP, "
                    "and review authentication activity for the account."
                ),
            }
        )

    return alerts
