#!/usr/bin/env python3

import datetime
import shlex

def parse_event_line(line):
    """Parse a single synthetic Windows Security Event log line."""

    line = line.strip()
    if not line:
        return None

    parts = shlex.split(line)

    event = {}

    timestamp_str = parts[0]

    try:
        event["timestamp"] = datetime.datetime.fromisoformat(timestamp_str)
    except ValueError:
        raise ValueError(f"Invalid timestamp: {timestamp_str}")

    for token in parts[1:]:
        if "=" not in token:
            continue

        key, value = token.split("=", 1)

        if key == "EVENT_ID":
            try:
                event[key] = int(value)
            except ValueError:
                event[key] = value
        else:
            event[key] = value

    return event

def parse_log_file(path):
    """Parse a Windows Security log file into structured events."""

    events = []

    with open(path, "r") as f:
        for line in f:
            if line.strip():
                events.append(parse_event_line(line))

    return events

def normalize_event(event):
    """Return a normalized event dictionary with standard fields."""

    return {
        "timestamp": event.get("timestamp"),
        "host": event.get("HOST"),
        "event_id": event.get("EVENT_ID"),
        "user": event.get("USER"),
        "source_ip": event.get("SRC_IP"),
        "process": event.get("PROCESS"),
        "status": event.get("STATUS"),
        "raw": event,
    }

def load_events(path):
    """Load and normalize all events from a log file."""

    return [normalize_event(e) for e in parse_log_file(path)]
