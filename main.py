from pathlib import Path

from dashboards.dashboard_generator import generate_dashboard
from engine.detection_engine import run_detections, summarize_alerts
from parser.windows_event_parser import load_events
from reporting.report_generator import (
    generate_html_report,
    generate_json_report,
)


BASE_DIR = Path(__file__).resolve().parent

SAMPLE_LOG = (
    BASE_DIR
    / "samples"
    / "windows_security_events.log"
)

REPORT_DIR = (
    BASE_DIR
    / "reports"
    / "generated"
)

JSON_REPORT = (
    REPORT_DIR
    / "windows_security_alerts.json"
)

HTML_REPORT = (
    REPORT_DIR
    / "windows_security_report.html"
)

DASHBOARD_REPORT = (
    REPORT_DIR
    / "cybernova_soc_dashboard.html"
)


def main():
    print("=" * 60)
    print("CYBERNOVA WINDOWS SECURITY MONITORING LAB")
    print("=" * 60)

    print(
        f"\nLoading events from: {SAMPLE_LOG}"
    )

    events = load_events(SAMPLE_LOG)

    print(
        f"Events loaded: {len(events)}"
    )

    alerts = run_detections(events)

    summary = summarize_alerts(alerts)

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    generate_json_report(
        alerts,
        JSON_REPORT,
    )

    generate_html_report(
        alerts,
        HTML_REPORT,
    )

    generate_dashboard(
        alerts,
        DASHBOARD_REPORT,
    )

    print("\nDetection Summary")
    print("-" * 30)

    for severity, count in summary.items():
        print(f"{severity}: {count}")

    print("\nReports generated:")

    print(
        f"JSON: {JSON_REPORT}"
    )

    print(
        f"HTML: {HTML_REPORT}"
    )

    print(
        f"Dashboard: {DASHBOARD_REPORT}"
    )

    print(
        "\nDetection lab completed successfully."
    )


if __name__ == "__main__":
    main()
