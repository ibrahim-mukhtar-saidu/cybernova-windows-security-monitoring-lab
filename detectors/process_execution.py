#!/usr/bin/env python3

RULE_NAME = "Suspicious Process Execution"
SEVERITY = "MEDIUM"
MITRE_ATTACK = "T1059 - Command and Scripting Interpreter"

SUSPICIOUS_PROCESSES = {
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
}

SUSPICIOUS_PATTERNS = [
    "whoami",
    "net user",
    "net localgroup",
    "powershell",
    "encodedcommand",
    "downloadstring",
]


def detect(events):
    """
    Detect potentially suspicious Windows process execution.

    Event ID:
        4688 = A new process has been created.

    Detection:
        Identify process executions involving suspicious
        process names or command-line patterns.

    Note:
        Process execution is not inherently malicious.
        Matches require analyst investigation and context.
    """

    alerts = []

    for event in events:
        if event.get("event_id") != 4688:
            continue

        raw = event.get("raw", {})

        process = str(
            event.get("process") or ""
        ).lower()

        parent_process = str(
            raw.get("PARENT_PROCESS") or ""
        )

        command = str(
            raw.get("COMMAND") or ""
        )

        command_lower = command.lower()

        matched_patterns = []

        if process in SUSPICIOUS_PROCESSES:
            matched_patterns.append(
                f"process:{process}"
            )

        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in command_lower:
                matched_patterns.append(pattern)

        if not matched_patterns:
            continue

        alerts.append(
            {
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "mitre_attack": MITRE_ATTACK,
                "affected_user": event.get("user"),
                "host": event.get("host"),
                "process": process,
                "parent_process": parent_process,
                "command": command,
                "matched_patterns": matched_patterns,
                "timestamp": event.get("timestamp").isoformat(),
                "risk": "MEDIUM",
                "related_events": [event],
                "timeline": [
                    {
                        "timestamp": event.get(
                            "timestamp"
                        ).isoformat(),
                        "event_id": event.get(
                            "event_id"
                        ),
                        "user": event.get("user"),
                        "process": process,
                        "parent_process": parent_process,
                        "command": command,
                    }
                ],
                "recommendation": (
                    "Review the process execution in context. "
                    "Validate the parent-child process relationship, "
                    "confirm whether the command was authorized, "
                    "identify the account responsible, and correlate "
                    "with nearby authentication and PowerShell activity."
                ),
                "false_positive_note": (
                    "Command interpreters and administrative utilities "
                    "can be legitimate. Determine whether the process, "
                    "parent process, command line, user, and timing are "
                    "consistent with expected administrative activity."
                ),
            }
        )

    return alerts
