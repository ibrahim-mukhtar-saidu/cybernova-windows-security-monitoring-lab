import unittest
from datetime import datetime
from pathlib import Path
import tempfile

from parser.windows_event_parser import (
    parse_event_line,
    parse_log_file,
    normalize_event,
    load_events,
)


class TestWindowsEventParser(unittest.TestCase):

    def test_parse_valid_event_line(self):
        line = (
            "2026-08-10T10:00:00 "
            "EVENT_ID=4625 "
            "HOST=WIN-DC01 "
            "USER=lab-admin "
            "SRC_IP=203.0.113.25 "
            "STATUS=0xC000006A"
        )

        event = parse_event_line(line)

        self.assertIsInstance(event["timestamp"], datetime)
        self.assertEqual(event["EVENT_ID"], 4625)
        self.assertEqual(event["HOST"], "WIN-DC01")
        self.assertEqual(event["USER"], "lab-admin")
        self.assertEqual(event["SRC_IP"], "203.0.113.25")
        self.assertEqual(event["STATUS"], "0xC000006A")

    def test_parse_empty_line(self):
        self.assertIsNone(parse_event_line(""))

    def test_invalid_timestamp_raises_error(self):
        line = (
            "not-a-timestamp "
            "EVENT_ID=4625 "
            "HOST=WIN-DC01"
        )

        with self.assertRaises(ValueError):
            parse_event_line(line)

    def test_event_id_is_converted_to_integer(self):
        line = (
            "2026-08-10T10:00:00 "
            "EVENT_ID=4688 "
            "HOST=WIN-DC01"
        )

        event = parse_event_line(line)

        self.assertIsInstance(event["EVENT_ID"], int)
        self.assertEqual(event["EVENT_ID"], 4688)

    def test_normalize_event(self):
        event = {
            "timestamp": datetime(2026, 8, 10, 10, 0, 0),
            "HOST": "WIN-DC01",
            "EVENT_ID": 4625,
            "USER": "lab-admin",
            "SRC_IP": "203.0.113.25",
            "PROCESS": "powershell.exe",
            "STATUS": "0xC000006A",
        }

        normalized = normalize_event(event)

        self.assertEqual(normalized["host"], "WIN-DC01")
        self.assertEqual(normalized["event_id"], 4625)
        self.assertEqual(normalized["user"], "lab-admin")
        self.assertEqual(
            normalized["source_ip"],
            "203.0.113.25",
        )
        self.assertEqual(
            normalized["process"],
            "powershell.exe",
        )
        self.assertEqual(
            normalized["status"],
            "0xC000006A",
        )
        self.assertEqual(normalized["raw"], event)

    def test_load_events_from_sample_log(self):
        sample_path = Path(
            "samples/windows_security_events.log"
        )

        events = load_events(sample_path)

        self.assertEqual(len(events), 10)

        for event in events:
            self.assertIn("timestamp", event)
            self.assertIn("event_id", event)
            self.assertIn("host", event)
            self.assertIn("user", event)
            self.assertIn("raw", event)

    def test_parse_log_file_with_temporary_file(self):
        content = (
            "2026-08-10T10:00:00 "
            "EVENT_ID=4625 "
            "HOST=WIN-DC01 "
            "USER=test-user\n"
            "2026-08-10T10:01:00 "
            "EVENT_ID=4624 "
            "HOST=WIN-DC01 "
            "USER=test-user\n"
        )

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
        ) as file:
            file.write(content)
            temp_path = file.name

        try:
            events = parse_log_file(temp_path)

            self.assertEqual(len(events), 2)
            self.assertEqual(events[0]["EVENT_ID"], 4625)
            self.assertEqual(events[1]["EVENT_ID"], 4624)
        finally:
            Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
