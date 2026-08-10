#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime


def html_escape(value):
    """Escape values before inserting them into HTML."""

    text = str(value)

    replacements = {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#x27;",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    return text


def generate_dashboard(alerts, output_path):
    """
    Generate a self-contained CyberNova SOC dashboard.
    """

    output_path = Path(output_path)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    detector_counts = {}

    for alert in alerts:
        severity = str(
            alert.get("severity", "LOW")
        ).upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

        detector = str(
            alert.get("detector")
            or alert.get("rule_name")
            or "Unknown"
        )

        detector_counts[detector] = (
            detector_counts.get(detector, 0) + 1
        )

    severity_cards = []

    for severity in (
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ):
        severity_cards.append(
            f"""
            <div class="card severity-{severity.lower()}">
                <div class="card-label">
                    {severity}
                </div>
                <div class="card-value">
                    {severity_counts[severity]}
                </div>
            </div>
            """
        )

    detector_rows = []

    for detector, count in sorted(
        detector_counts.items(),
        key=lambda item: (-item[1], item[0]),
    ):
        detector_rows.append(
            f"""
            <tr>
                <td>{html_escape(detector)}</td>
                <td>{count}</td>
            </tr>
            """
        )

    alert_rows = []

    for index, alert in enumerate(
        alerts,
        start=1,
    ):
        severity = str(
            alert.get("severity", "LOW")
        ).upper()

        timestamp = alert.get("timestamp", "-")

        if isinstance(timestamp, datetime):
            timestamp = timestamp.isoformat(
                timespec="seconds"
            )

        alert_rows.append(
            f"""
            <tr>
                <td>{index}</td>
                <td>
                    <span class="severity-badge
                    severity-{severity.lower()}">
                        {html_escape(severity)}
                    </span>
                </td>
                <td>
                    {html_escape(
                        alert.get("rule_name", "-")
                    )}
                </td>
                <td>
                    {html_escape(
                        alert.get("affected_user", "-")
                    )}
                </td>
                <td>
                    {html_escape(
                        alert.get("host", "-")
                    )}
                </td>
                <td>
                    {html_escape(
                        alert.get("source_ip", "-")
                    )}
                </td>
                <td>
                    {html_escape(
                        alert.get("mitre_attack", "-")
                    )}
                </td>
                <td>
                    {html_escape(timestamp)}
                </td>
            </tr>
            """
        )

    generated_at = datetime.now().isoformat(
        timespec="seconds"
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,
      initial-scale=1.0">

<title>CyberNova SOC Dashboard</title>

<style>

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    padding: 0;
    font-family:
        Arial, Helvetica, sans-serif;
    background: #0b1120;
    color: #e5e7eb;
}}

header {{
    padding: 30px 40px;
    background: #111827;
    border-bottom: 1px solid #263244;
}}

header h1 {{
    margin: 0;
    font-size: 28px;
}}

header p {{
    margin: 8px 0 0;
    color: #9ca3af;
}}

.container {{
    padding: 30px 40px;
}}

.cards {{
    display: grid;
    grid-template-columns:
        repeat(4, minmax(160px, 1fr));
    gap: 18px;
    margin-bottom: 30px;
}}

.card {{
    padding: 22px;
    border-radius: 10px;
    background: #111827;
    border: 1px solid #263244;
}}

.card-label {{
    font-size: 13px;
    font-weight: bold;
    letter-spacing: 1px;
}}

.card-value {{
    margin-top: 8px;
    font-size: 34px;
    font-weight: bold;
}}

.severity-critical {{
    border-left: 5px solid #dc2626;
}}

.severity-high {{
    border-left: 5px solid #ea580c;
}}

.severity-medium {{
    border-left: 5px solid #ca8a04;
}}

.severity-low {{
    border-left: 5px solid #16a34a;
}}

.section {{
    margin-bottom: 30px;
    padding: 24px;
    background: #111827;
    border: 1px solid #263244;
    border-radius: 10px;
}}

.section h2 {{
    margin-top: 0;
}}

.table-wrapper {{
    overflow-x: auto;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    min-width: 900px;
}}

th,
td {{
    padding: 12px;
    text-align: left;
    border-bottom: 1px solid #263244;
}}

th {{
    color: #93c5fd;
    font-size: 13px;
}}

td {{
    font-size: 13px;
}}

tr:hover {{
    background: #172033;
}}

.severity-badge {{
    display: inline-block;
    padding: 4px 8px;
    border-radius: 5px;
    font-size: 11px;
    font-weight: bold;
}}

.severity-badge.severity-critical {{
    background: #7f1d1d;
    color: #fecaca;
}}

.severity-badge.severity-high {{
    background: #7c2d12;
    color: #fed7aa;
}}

.severity-badge.severity-medium {{
    background: #713f12;
    color: #fef08a;
}}

.severity-badge.severity-low {{
    background: #14532d;
    color: #bbf7d0;
}}

.summary-table {{
    max-width: 700px;
}}

footer {{
    padding: 25px 40px;
    color: #6b7280;
    font-size: 12px;
    border-top: 1px solid #263244;
}}

@media (max-width: 800px) {{
    header,
    .container,
    footer {{
        padding-left: 20px;
        padding-right: 20px;
    }}

    .cards {{
        grid-template-columns:
            repeat(2, minmax(140px, 1fr));
    }}
}}

</style>
</head>

<body>

<header>
    <h1>CYBERNOVA SOC DASHBOARD</h1>
    <p>
        Windows Security Monitoring Laboratory
    </p>
</header>

<div class="container">

    <div class="cards">

        <div class="card">
            <div class="card-label">
                TOTAL ALERTS
            </div>
            <div class="card-value">
                {len(alerts)}
            </div>
        </div>

        {"".join(severity_cards)}

    </div>

    <div class="section">
        <h2>Detection Rules</h2>

        <div class="table-wrapper">
            <table class="summary-table">
                <thead>
                    <tr>
                        <th>Detection Rule</th>
                        <th>Alerts</th>
                    </tr>
                </thead>

                <tbody>
                    {"".join(detector_rows)}
                </tbody>
            </table>
        </div>
    </div>

    <div class="section">
        <h2>Security Alerts</h2>

        <div class="table-wrapper">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Rule</th>
                        <th>User</th>
                        <th>Host</th>
                        <th>Source IP</th>
                        <th>MITRE ATT&amp;CK</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>

                <tbody>
                    {"".join(alert_rows)}
                </tbody>
            </table>
        </div>
    </div>

</div>

<footer>
    CyberNova Windows Security Monitoring Lab |
    Synthetic laboratory telemetry |
    Generated: {html_escape(generated_at)}
</footer>

</body>
</html>
"""

    clean_html = "\n".join(
        line.rstrip()
        for line in html.splitlines()
    ) + "\n"

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        file.write(clean_html)

    return output_path


if __name__ == "__main__":
    print(
        "Dashboard generator module loaded successfully."
    )
