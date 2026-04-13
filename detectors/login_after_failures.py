#!/usr/bin/env python3

from collections import defaultdict
from datetime import timedelta

RULE_NAME = "Successful Login After Multiple Failures"
SEVERITY = "CRITICAL"
MITRE_ATTACK = "T1078 - Valid Accounts"


def detect(events, threshold=3, window_minutes=10):
    """
    Detect a successful logon following multiple failed logons.

    Event IDs:
        4625 = Failed logon
        4624 = Successful logon

    Detection:
        Three or more failed logons from the same user and source IP
        followed by a successful logon within the configured time window.
    """

    grouped = defaultdict(list)

    for event in events:
        user = event.get("user")
        source_ip = event.get("source_ip")

        if not user or not source_ip:
            continue

        grouped[(user, source_ip)].append(event)

    alerts = []

    for (user, source_ip), user_events in grouped.items():

        user_events.sort(
            key=lambda event: event.get("timestamp")
        )

        for index, event in enumerate(user_events):

            if event.get("event_id") != 4624:
                continue

            success_time = event.get("timestamp")

            window_start = success_time - timedelta(
                minutes=window_minutes
            )

            failed_events = [
                previous
                for previous in user_events[:index]
                if (
                    previous.get("event_id") == 4625
                    and previous.get("timestamp") >= window_start
                    and previous.get("timestamp") < success_time
                )
            ]

            if len(failed_events) < threshold:
                continue

            related_events = failed_events + [event]

            timeline = []

            for related in related_events:
                timeline.append(
                    {
                        "timestamp": related.get(
                            "timestamp"
                        ).isoformat(),
                        "event_id": related.get("event_id"),
                        "user": related.get("user"),
                        "source_ip": related.get(
                            "source_ip"
                        ),
                        "status": related.get("status"),
                    }
                )

            alerts.append(
                {
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "mitre_attack": MITRE_ATTACK,
                    "affected_user": user,
                    "source_ip": source_ip,
                    "host": event.get("host"),
                    "failed_count": len(failed_events),
                    "success_time": success_time.isoformat(),
                    "first_failed": failed_events[0].get(
                        "timestamp"
                    ).isoformat(),
                    "last_failed": failed_events[-1].get(
                        "timestamp"
                    ).isoformat(),
                    "related_events": related_events,
                    "timeline": timeline,
                    "risk": "CRITICAL",
                    "recommendation": (
                        "Investigate the successful authentication "
                        "immediately. Validate the source IP, "
                        "confirm whether the account owner expected "
                        "the activity, review privilege changes, "
                        "and examine subsequent account activity."
                    ),
                }
            )

    return alerts
