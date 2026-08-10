# CYBERNOVA Windows Security Monitoring Lab

A Python-based Windows Security Monitoring and SOC Detection Lab designed to simulate security-event analysis, threat detection, alert generation, reporting, and SOC-style visualization using synthetic Windows Security Event telemetry.

> **Project type:** Cybersecurity / SOC / Threat Detection / Security Monitoring
> **Language:** Python
> **Environment:** Linux / Python 3
> **Data:** Synthetic laboratory Windows Security Events
> **Testing:** 33 automated tests

---

## Overview

The CYBERNOVA Windows Security Monitoring Lab demonstrates a lightweight security monitoring workflow similar to a Security Operations Center (SOC).

The project takes structured synthetic Windows Security Event data, parses and normalizes the events, runs multiple detection rules, generates security alerts, and produces analyst-friendly reports and a SOC dashboard.

### Monitoring Pipeline

```text
Synthetic Windows Security Events
              │
              ▼
      Windows Event Parser
              │
              ▼
       Event Normalization
              │
              ▼
       Detection Engine
              │
      ┌───────┴────────┐
      ▼                ▼
 Detection Rules    Alert Generation
      │                │
      └───────┬────────┘
              ▼
       Severity Summary
              │
       ┌──────┴──────┐
       ▼             ▼
   JSON Report    HTML Report
       │             │
       └──────┬──────┘
              ▼
       CYBERNOVA SOC
          Dashboard
```

---

## Key Features

* Synthetic Windows Security Event telemetry
* Windows event parsing and normalization
* Centralized detection engine
* Multiple security detection rules
* Alert severity classification
* MITRE ATT&CK technique references
* JSON security alert reporting
* Analyst-friendly HTML reporting
* Self-contained SOC dashboard
* HTML output escaping for untrusted alert data
* Automated unit and integration testing
* Python compilation validation
* Git-based project version control

---

## Detection Rules

The current detection engine contains eight detection rules:

| Detection Rule                           | Purpose                                                       | Severity |
| ---------------------------------------- | ------------------------------------------------------------- | -------- |
| Repeated Failed Logons                   | Detects repeated authentication failures                      | HIGH     |
| Successful Login After Multiple Failures | Detects successful authentication following multiple failures | CRITICAL |
| New User Account Creation                | Detects creation of new user accounts                         | HIGH     |
| Privileged Group Membership Change       | Detects changes to privileged group membership                | HIGH     |
| Suspicious PowerShell Execution          | Detects suspicious PowerShell activity                        | HIGH     |
| Suspicious Process Execution             | Detects suspicious process execution                          | MEDIUM   |
| Account Lockout                          | Detects account lockout activity                              | MEDIUM   |
| Windows Security Log Cleared             | Detects clearing of Windows Security logs                     | HIGH     |

---

## Sample Detection Results

The current synthetic dataset contains:

```text
Events loaded: 10
Alerts generated: 8
```

Severity summary:

```text
CRITICAL: 1
HIGH:     5
MEDIUM:   2
LOW:      0
```

This allows the project to demonstrate how raw security telemetry can be transformed into prioritized security alerts.

---

## MITRE ATT&CK

The detection rules reference relevant MITRE ATT&CK techniques, including examples such as:

* **T1110 — Brute Force**
* **T1070.001 — Clear Windows Event Logs**
* **T1078 — Valid Accounts**
* **T1059 — Command and Scripting Interpreter**

The mappings are intended for educational and laboratory purposes using synthetic telemetry.

---

## Project Structure

```text
cybernova-windows-security-monitoring-lab/
│
├── dashboards/
│   └── dashboard_generator.py
│
├── detectors/
│   ├── failed_logon.py
│   ├── login_after_failures.py
│   ├── user_creation.py
│   ├── privilege_change.py
│   ├── powershell_execution.py
│   ├── process_execution.py
│   ├── account_lockout.py
│   └── log_clearing.py
│
├── engine/
│   └── detection_engine.py
│
├── parser/
│   └── windows_event_parser.py
│
├── reporting/
│   └── report_generator.py
│
├── samples/
│   └── windows_security_events.log
│
├── reports/
│   └── generated/
│       ├── windows_security_alerts.json
│       ├── windows_security_report.html
│       └── cybernova_soc_dashboard.html
│
├── tests/
│   ├── test_all_detectors.py
│   ├── test_detectors.py
│   ├── test_parser.py
│   ├── test_reporting.py
│   └── test_dashboard.py
│
├── main.py
├── requirements.txt
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/ibrahim-mukhtar-saidu/cybernova-windows-security-monitoring-lab.git
```

Enter the project directory:

```bash
cd cybernova-windows-security-monitoring-lab
```

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

Install the project requirements:

```bash
pip install -r requirements.txt
```

---

## Running the Detection Lab

Run the main detection pipeline:

```bash
python3 main.py
```

Expected output includes:

```text
CYBERNOVA WINDOWS SECURITY MONITORING LAB

Events loaded: 10

Detection Summary

total_alerts: 8
critical: 1
high: 5
medium: 2
low: 0
```

The generated reports are written to:

```text
reports/generated/
```

---

## Generating the SOC Dashboard

The dashboard can be generated from the parsed events and detection results.

Example:

```python
from pathlib import Path

from parser.windows_event_parser import load_events
from engine.detection_engine import run_detections
from dashboards.dashboard_generator import generate_dashboard

events = load_events(
    "samples/windows_security_events.log"
)

alerts = run_detections(events)

output = Path(
    "reports/generated/cybernova_soc_dashboard.html"
)

generate_dashboard(alerts, output)
```

The resulting dashboard is:

```text
reports/generated/cybernova_soc_dashboard.html
```

The dashboard provides:

* Total alert count
* Severity summary
* Detection-rule summary
* Security-alert table
* User information
* Host information
* Source IP information
* MITRE ATT&CK references
* Alert timestamps

---

## Testing

The project currently contains **33 automated tests**.

Run the complete test suite:

```bash
python3 -m pytest -q
```

Expected result:

```text
33 passed
```

Run parser tests:

```bash
python3 -m pytest -q tests/test_parser.py
```

Run reporting tests:

```bash
python3 -m pytest -q tests/test_reporting.py
```

Run dashboard tests:

```bash
python3 -m pytest -q tests/test_dashboard.py
```

Run detector tests:

```bash
python3 -m pytest -q tests/test_detectors.py
```

---

## Code Validation

Python compilation can be checked with:

```bash
python3 -m compileall -q \
parser \
detectors \
engine \
reporting \
dashboards \
main.py \
tests
```

Git whitespace validation:

```bash
git diff --check
```

---

## Security Considerations

The dashboard and reporting components escape alert values before inserting them into generated HTML.

This helps prevent alert data containing HTML or script content from being interpreted as executable markup when viewed in the generated report.

The test suite includes validation for this behavior.

Example test input:

```text
<script>alert('x')</script>
```

The dashboard generator escapes the value before inserting it into the HTML document.

---

## Laboratory Scope

This project is designed for **defensive cybersecurity education and portfolio development**.

The included Windows Security Event data is synthetic laboratory telemetry and does not represent real production security logs.

No real credentials, personal information, or production system telemetry are required.

---

## What This Project Demonstrates

This project demonstrates practical experience with:

* Python security automation
* Security event parsing
* Log normalization
* Detection engineering
* Alert generation
* Security severity classification
* SOC monitoring concepts
* MITRE ATT&CK mapping
* Security reporting
* Dashboard generation
* Automated testing
* Defensive security engineering
* Git/GitHub project management

---

## Future Improvements

Potential future versions may include:

* Real Windows Event Log ingestion
* Sigma rule support
* Additional MITRE ATT&CK detections
* Configurable detection thresholds
* Alert filtering and search
* Dashboard charts
* Detection-rule configuration files
* CSV report generation
* Alert deduplication
* Time-based correlation
* Automated incident summaries
* Docker-based laboratory deployment
* CI testing with GitHub Actions

---

## Project Status

**Current status: Active development**

Current capabilities include:

```text
8 Detection Rules
10 Synthetic Events
8 Generated Alerts
4 Severity Categories
JSON Reporting
HTML Reporting
SOC Dashboard
33 Automated Tests
```

---

## Author

**Ibrahim Mukhtar Saidu**

Cybersecurity learner and project developer focused on:

* Security Operations
* Threat Detection
* Security Monitoring
* Python Security Automation
* Linux
* Defensive Cybersecurity

### CYBERNOVA AI

This project is part of the CYBERNOVA AI cybersecurity portfolio.

---

## Disclaimer

This project is an educational cybersecurity laboratory.

All included security events are synthetic. The project is intended for defensive security learning, detection engineering practice, SOC concepts, and portfolio demonstration.README.md

