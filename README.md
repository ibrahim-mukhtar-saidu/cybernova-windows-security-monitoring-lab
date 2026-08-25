# CYBERNOVA Windows Security Monitoring Lab

A Python-based Windows Security Monitoring and SOC Detection Lab designed to simulate security-event analysis, threat detection, alert generation, investigation context, reporting, and SOC-style visualization using synthetic Windows Security Event telemetry.

> **Project type:** Cybersecurity / SOC / Threat Detection / Security Monitoring
> **Language:** Python
> **Environment:** Linux / Python 3
> **Data:** Synthetic laboratory Windows Security Events
> **Testing:** 33 automated tests
> **Status:** Functional and tested

---

## Overview

The CYBERNOVA Windows Security Monitoring Lab demonstrates a lightweight defensive security-monitoring workflow similar to processes used in a Security Operations Center (SOC).

The project takes synthetic Windows Security Event data, parses and normalizes the events, executes multiple detection rules, generates investigation-oriented security alerts, summarizes severity, and produces JSON, HTML, and SOC dashboard outputs.

The project is intentionally designed as a laboratory environment rather than a production SIEM.

---

## Monitoring Pipeline

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
        ┌─────┴─────┐
        │           │
        ▼           ▼
 Detection Rules   Correlation
        │           │
        └─────┬─────┘
              ▼
        Security Alerts
              │
              ▼
       Severity Summary
              │
       ┌──────┼──────────┐
       ▼      ▼          ▼
      JSON   HTML     SOC Dashboard
    Report   Report
```

The three reporting outputs are generated from the unified alert set. The dashboard does not depend on the JSON or HTML report files.

## Key Features
Synthetic Windows Security Event telemetry
Windows event parsing and normalization
Centralized detection engine
Eight security detection rules
Authentication-failure correlation
Alert severity classification
Investigation timelines
Related-event context
MITRE ATT&CK technique references
Analyst recommendations
False-positive guidance
JSON security alert reporting
Analyst-friendly HTML reporting
Self-contained SOC dashboard
HTML output escaping for untrusted alert data
Automated parser, detector, engine, reporting, and dashboard tests
Python compilation validation
Git-based project version control
## Detection Rules

The current detection engine contains eight detection rules.

Detection Rule	Windows Event ID	MITRE ATT&CK	Severity
Repeated Failed Logons	4625	T1110 — Brute Force	HIGH
Successful Login After Multiple Failures	4624 / 4625	T1078 — Valid Accounts	CRITICAL
New User Account Creation	4720	T1136 — Create Account	HIGH
Privileged Group Membership Change	4728	T1098 — Account Manipulation	HIGH
Suspicious PowerShell Execution	4104	T1059.001 — PowerShell	HIGH
Suspicious Process Execution	4688	T1059 — Command and Scripting Interpreter	MEDIUM
Account Lockout	4740	Windows account lockout monitoring	MEDIUM
Windows Security Log Cleared	1102	T1070.001 — Clear Windows Event Logs	HIGH
### Detection Logic
### Repeated Failed Logons

Detects multiple failed authentication attempts associated with the same account and source context.

### Successful Login After Multiple Failures

Correlates at least three failed logons followed by a successful authentication within the configured time window.

This provides stronger context than treating each authentication event independently.

### New User Account Creation

Detects Windows user-account creation events and identifies both the account creator and newly created account.

### Privileged Group Membership Change

Detects membership changes involving privileged groups such as:

Administrators
Domain Admins
Enterprise Admins
Backup Operators
Account Operators
### Suspicious PowerShell Execution

Identifies PowerShell Script Block Logging events containing suspicious command patterns such as download or encoded-command activity.

A match does not automatically indicate malicious activity because PowerShell is also commonly used for legitimate administration and automation.

### Suspicious Process Execution

Examines process-creation events for suspicious process names and command-line patterns.

The detector also preserves parent-process information for investigation.

### Account Lockout

Detects Windows account-lockout activity and identifies the affected account.

### Windows Security Log Cleared

Detects Security Event Log clearing activity, which can be relevant to defense-evasion investigations.

## Sample Detection Results

The current synthetic dataset contains:

Events loaded: 10
Alerts generated: 8

Severity summary:

CRITICAL: 1
HIGH:     5
MEDIUM:   2
LOW:      0

The sample telemetry demonstrates a multi-stage suspicious activity sequence involving authentication failures, successful authentication, privilege modification, PowerShell execution, account creation, process execution, log clearing, and account lockout.

## SOC Investigation Scenario

The sample telemetry can be investigated as a chronological security incident.

Example timeline:

09:01:15  Failed logon
09:02:10  Failed logon
09:03:01  Failed logon
09:05:44  Successful logon
09:06:30  Privileged group membership change
09:08:05  Suspicious PowerShell execution
09:10:12  Windows Security log cleared
09:12:30  New user account created
09:14:22  Suspicious process execution
09:16:40  Account lockout
Analyst interpretation

An analyst could investigate the sequence as follows:

Identify the repeated failed authentication attempts.
Determine whether the subsequent successful login is associated with the same user and source IP.
Validate whether the authentication was expected.
Investigate the privileged group membership change.
Review the PowerShell command and determine whether it was authorized.
Examine the parent-child process relationship for suspicious execution.
Investigate the newly created account and its privileges.
Treat the Security Event Log clearing as a potentially important defense-evasion indicator.
Correlate the account-lockout event with the preceding authentication activity.
Review all related events and timestamps before determining incident severity.

The generated alerts preserve related events and timeline information to support this investigation workflow.

Alert Investigation Context

Generated alerts may contain investigation-oriented fields such as:

Affected user
Host
Source IP
Event ID
Timestamp
Failed authentication count
First failed authentication
Last failed authentication
Successful authentication time
Related events
Timeline
Matched detection patterns
Parent process
Command line
Risk classification
Analyst recommendation
False-positive guidance

This allows the project to demonstrate more than simple pattern matching.

False Positives and Analyst Validation

Detection matches should be treated as investigation leads, not automatic proof of compromise.

Examples:

PowerShell

PowerShell is widely used for legitimate administration, configuration management, and automation.

An analyst should validate:

User
Host
Command
Timing
Administrative authorization
Related authentication events
Process Execution

Utilities such as cmd.exe, PowerShell, and other Windows administrative tools can be legitimate.

The analyst should examine:

Process name
Parent process
Command line
User
Host
Timing
Related security events

Detection engineering should therefore combine rule matches with contextual investigation.

## MITRE ATT&CK

The detection rules reference relevant MITRE ATT&CK techniques.

Current mappings include:

Detection	MITRE ATT&CK
Repeated Failed Logons	T1110 — Brute Force
Successful Login After Multiple Failures	T1078 — Valid Accounts
New User Account Creation	T1136 — Create Account
Privileged Group Membership Change	T1098 — Account Manipulation
Suspicious PowerShell Execution	T1059.001 — PowerShell
Suspicious Process Execution	T1059 — Command and Scripting Interpreter
Windows Security Log Cleared	T1070.001 — Clear Windows Event Logs

The mappings are used for defensive laboratory analysis and educational purposes using synthetic telemetry.

## Screenshots & Evidence

The following screenshots demonstrate the detection pipeline, SOC dashboard, and automated testing results.

## Detection Run

The detection engine processes the synthetic Windows Security Event dataset and generates prioritized security alerts.

## CYBERNOVA SOC Dashboard

The self-contained SOC dashboard provides a visual overview of alert severity, detection rules, affected users, hosts, source IPs, MITRE ATT&CK mappings, and timestamps.

## SOC Dashboard — Detailed View

An additional dashboard view showing the generated security monitoring results.

## Automated Tests

The project includes automated parser, detector, engine, reporting, and dashboard tests.

## Project Structure
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
├── screenshots/
│   ├── detection-run.png
│   ├── cybernova-soc-dashboard.png
│   ├── cybernova-soc-dashboard2.png
│   └── tests-passing.png
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
├── pytest.ini
└── README.md
## Installation

Clone the repository:

git clone https://github.com/ibrahim-mukhtar-saidu/cybernova-windows-security-monitoring-lab.git

Enter the project directory:

cd cybernova-windows-security-monitoring-lab

Create a virtual environment:

python3 -m venv venv

Activate it:

source venv/bin/activate

Install the project requirements:

pip install -r requirements.txt
## Running the Detection Lab

Run the complete detection pipeline:

python3 main.py

Expected output includes:

CYBERNOVA WINDOWS SECURITY MONITORING LAB

Events loaded: 10

Detection Summary
------------------------------
total_alerts: 8
critical: 1
high: 5
medium: 2
low: 0

Reports generated:
JSON: .../reports/generated/windows_security_alerts.json
HTML: .../reports/generated/windows_security_report.html
Dashboard: .../reports/generated/cybernova_soc_dashboard.html

Detection lab completed successfully.

The generated outputs are written to:

reports/generated/
Generated Outputs

The pipeline produces three portfolio-ready artifacts:

JSON Alert Report
reports/generated/windows_security_alerts.json

Contains structured security alerts suitable for machine-readable analysis.

HTML Security Report
reports/generated/windows_security_report.html

Provides an analyst-friendly tabular report containing detection, severity, user, host, MITRE ATT&CK, and risk information.

SOC Dashboard
reports/generated/cybernova_soc_dashboard.html

Provides a self-contained visual dashboard containing:

Total alert count
Severity summary
Detection-rule summary
Security-alert table
User information
Host information
Source IP information
MITRE ATT&CK references
Alert timestamps

The dashboard is automatically generated by main.py.

It can also be generated independently:

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
## Testing

The project currently contains 33 automated tests covering:

Event parsing
Event normalization
Individual detection rules
Detection-engine integration
Severity summarization
JSON reporting
HTML reporting
Dashboard generation
HTML output escaping
Report-directory creation

Run the complete test suite:

python3 -m pytest -q

Expected result:

33 passed

Individual test groups can also be executed:

python3 -m pytest -q tests/test_parser.py
python3 -m pytest -q tests/test_reporting.py
python3 -m pytest -q tests/test_dashboard.py
python3 -m pytest -q tests/test_detectors.py
## Code Validation

Python compilation can be checked with:

python3 -m compileall -q \
parser \
detectors \
engine \
reporting \
dashboards \
main.py \
tests

Git whitespace validation:

git diff --check
## Security Considerations

The reporting and dashboard components escape alert values before inserting them into generated HTML.

This helps prevent alert data containing HTML or script content from being interpreted as executable markup when viewed in the generated reports.

The test suite includes validation for this behavior.

Example test input:

<script>alert('x')</script>

The dashboard generator escapes the value before inserting it into the HTML document.

## Laboratory Scope

This project is designed for defensive cybersecurity education and portfolio development.

The included Windows Security Event data is synthetic laboratory telemetry and does not represent real production security logs.

No real credentials, personal information, or production system telemetry are required.

Limitations

This project is intentionally lightweight and laboratory-focused.

Current limitations include:

Uses synthetic Windows Security Event telemetry.
Does not ingest native Windows EVTX files.
Does not provide real-time event collection.
Does not integrate with a production SIEM.
Detection thresholds are currently defined in Python code.
Detection rules are not yet externally configurable.
Generated dashboards are static HTML artifacts.
No persistent alert database is included.
No authentication or authorization layer is implemented for dashboard access.
Detection logic is intentionally simplified for educational use.
MITRE ATT&CK mappings provide contextual references rather than complete ATT&CK coverage.

These limitations distinguish the project from a production security-monitoring platform while keeping the laboratory reproducible and easy to understand.

## Future Improvements

Potential future versions may include:

Native Windows Event Log / EVTX ingestion
Sigma rule support
Additional MITRE ATT&CK detections
Configurable detection thresholds
External detection-rule configuration
Alert filtering and search
Dashboard charts and visualizations
CSV report generation
Alert deduplication
More advanced time-based correlation
Automated incident summaries
Persistent alert storage
SIEM integration
Docker-based laboratory deployment
GitHub Actions CI testing
## What This Project Demonstrates

This project demonstrates practical experience with:

Python security automation
Security event parsing
Log normalization
Detection engineering
Authentication-event correlation
Alert generation
Security severity classification
SOC monitoring concepts
Investigation-oriented alert context
MITRE ATT&CK mapping
Security reporting
Dashboard generation
HTML output security
Automated testing
Defensive security engineering
Git/GitHub project management
## Project Status

Current status: Functional and tested

Current capabilities:

8 Detection Rules
10 Synthetic Events
8 Generated Alerts
4 Severity Categories
JSON Reporting
HTML Reporting
SOC Dashboard
33 Automated Tests

The project is considered functionally complete for its current laboratory scope.

Future improvements may extend its event ingestion, detection capabilities, correlation logic, reporting, deployment, and SIEM integration.

## Author

Ibrahim Mukhtar Saidu

Cybersecurity learner and project developer focused on:

Security Operations
Threat Detection
Security Monitoring
Python Security Automation
Linux
Defensive Cybersecurity
CYBERNOVA AI

This project is part of the CYBERNOVA AI cybersecurity portfolio.

## Disclaimer

This project is an educational cybersecurity laboratory.

All included security events are synthetic. The project is intended for defensive security learning, detection engineering practice, SOC investigation concepts, and portfolio demonstration.
