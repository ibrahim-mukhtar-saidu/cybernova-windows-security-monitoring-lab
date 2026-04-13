# CYBERNOVA Windows Security Monitoring Lab

> **A Python-based Windows security monitoring and detection-engineering laboratory for SOC analysis, threat detection, MITRE ATT&CK mapping, automated alerting, testing, and security reporting.**

![Python](https://img.shields.io/badge/Python-3.13-blue)
![Tests](https://img.shields.io/badge/tests-13%20passed-brightgreen)
![Detection Rules](https://img.shields.io/badge/detection%20rules-8-orange)
![MITRE ATT\&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-mapped-red)
![Platform](https://img.shields.io/badge/platform-Windows%20Security%20Events-lightgrey)
![Project](https://img.shields.io/badge/project-CYBERNOVA%20AI-purple)

## Overview

The **CYBERNOVA Windows Security Monitoring Lab** is a defensive cybersecurity project designed to demonstrate practical **SOC analyst** and **detection-engineering** capabilities using Python.

The project ingests structured Windows Security Event data, parses the events, applies multiple detection rules, generates investigation-focused alerts, maps detections to **MITRE ATT&CK techniques**, and produces machine-readable and human-readable security reports.

The laboratory is built around a realistic attack-investigation scenario in which suspicious authentication, account, privilege, PowerShell, process, account-lockout, and log-clearing activity occurs on a simulated Windows host.

All event data included in this repository is **synthetic laboratory data** created for defensive security testing and portfolio demonstration.

---

## Portfolio Objective

This project demonstrates the ability to:

* Analyze Windows Security Event data
* Build security detection logic in Python
* Identify suspicious authentication patterns
* Detect account and privilege changes
* Analyze PowerShell and process execution
* Detect Windows Security log clearing
* Generate structured security alerts
* Map detections to MITRE ATT&CK
* Assign severity and risk levels
* Document false-positive considerations
* Correlate security activity for investigation
* Generate JSON and HTML security reports
* Build automated tests for detection logic
* Organize a modular cybersecurity codebase
* Apply software-engineering practices to security tooling

The goal is not simply to detect events, but to demonstrate how a security analyst or detection engineer can turn raw security telemetry into **actionable investigation signals**.

---

# Detection Capabilities

The current detection engine contains **8 security detection rules**.

| # | Detection                                |         Windows Event ID | Severity | MITRE ATT&CK                              |
| - | ---------------------------------------- | -----------------------: | -------- | ----------------------------------------- |
| 1 | Repeated Failed Logons                   |                     4625 | HIGH     | Authentication / Brute Force              |
| 2 | Successful Login After Multiple Failures |              4625 + 4624 | CRITICAL | T1078 - Valid Accounts                    |
| 3 | New User Account Creation                |                     4720 | HIGH     | T1136 - Create Account                    |
| 4 | Privileged Group Membership Change       | 4728/4732-style activity | HIGH     | T1098 - Account Manipulation              |
| 5 | Suspicious PowerShell Execution          |                     4104 | HIGH     | T1059.001 - PowerShell                    |
| 6 | Suspicious Process Execution             |                     4688 | MEDIUM   | T1059 - Command and Scripting Interpreter |
| 7 | Account Lockout                          |                     4740 | MEDIUM   | T1110 - Brute Force                       |
| 8 | Windows Security Log Cleared             |                     1102 | HIGH     | T1070.001 - Clear Windows Event Logs      |

> Detection severity represents the rule's investigation priority. A detection does not automatically mean that malicious activity has been confirmed.

---

# Example Investigation Scenario

The included synthetic event stream represents a sequence of suspicious activity involving:

```text
Multiple failed authentication attempts
        ↓
Successful authentication
        ↓
Privileged group membership change
        ↓
Suspicious PowerShell execution
        ↓
Security log clearing
        ↓
New account creation
        ↓
Suspicious process execution
        ↓
Account lockout
```

This sequence demonstrates why SOC investigations require **event correlation and context**, rather than treating individual log events as isolated incidents.

For example, a PowerShell command such as:

```text
Invoke-WebRequest http://example
```

may be legitimate administrative activity in one environment but suspicious in another.

The detection therefore produces an alert requiring analyst validation instead of claiming that the activity is automatically malicious.

---

# Detection Engine

The central detection engine provides a unified interface for running all available detection rules.

```text
Windows Security Events
          │
          ▼
   Event Parser
          │
          ▼
   Detection Engine
          │
    ┌─────┴─────┐
    │           │
    ▼           ▼
Detection     Detection
Rules         Correlation
    │           │
    └─────┬─────┘
          ▼
    Security Alerts
          │
     ┌────┴────┐
     ▼         ▼
   JSON       HTML
   Report     Report
```

The architecture separates parsing, detection, reporting, and testing so that individual components can be maintained and expanded independently.

---

# Project Structure

```text
cybernova-windows-security-monitoring-lab/
│
├── dashboards/
│   └── dashboard_generator.py
│
├── detectors/
│   ├── account_lockout.py
│   ├── failed_logon.py
│   ├── log_clearing.py
│   ├── login_after_failures.py
│   ├── powershell_execution.py
│   ├── privilege_change.py
│   ├── process_execution.py
│   └── user_creation.py
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
├── reports/
│   └── generated/
│       ├── windows_security_alerts.json
│       └── windows_security_report.html
│
├── samples/
│   └── windows_security_events.log
│
├── tests/
│   ├── test_all_detectors.py
│   ├── test_detectors.py
│   ├── test_parser.py
│   └── test_reporting.py
│
├── .gitignore
├── main.py
├── README.md
└── requirements.txt
```

---

# SOC Detection Workflow

The project follows a simplified security monitoring workflow:

### 1. Collect

Synthetic Windows Security Events are stored in the sample event log.

### 2. Parse

`parser/windows_event_parser.py` converts the raw event records into structured Python objects.

### 3. Detect

Individual detection modules analyze the structured events.

### 4. Correlate

The detection engine combines results from multiple rules into a unified alert collection.

### 5. Prioritize

Alerts receive severity and risk classifications such as:

```text
CRITICAL
HIGH
MEDIUM
LOW
```

### 6. Investigate

Alerts contain contextual information such as:

* affected user
* host
* source IP
* timestamp
* command
* process
* parent process
* matched patterns
* related events
* recommendations
* false-positive considerations

### 7. Report

The reporting layer produces:

* JSON security alert data
* HTML security reports

---

# Example Detection Output

A successful-login-after-failures detection produces an alert similar to:

```text
=== CYBERNOVA WINDOWS SECURITY ALERT ===
Rule:          Successful Login After Multiple Failures
Severity:      CRITICAL
MITRE ATT&CK:  T1078 - Valid Accounts
User:          lab-admin
Source IP:     203.0.113.25
Host:          WIN-DC01
Failed Logons: 3
Risk:          CRITICAL
```

The recommendation directs the analyst to validate the source IP, confirm whether the account owner expected the activity, review privilege changes, and examine subsequent account activity.

---

# False-Positive Awareness

A key objective of this project is to demonstrate that **detection does not equal attribution**.

Several rules explicitly account for legitimate administrative behavior.

Examples include:

* PowerShell used for legitimate automation
* Account creation performed by authorized administrators
* Privileged group changes during approved maintenance
* Account lockouts caused by stale credentials
* Security log clearing during authorized incident response
* Command-line utilities used by system administrators

The alerts therefore provide investigation guidance rather than automatically labeling activity as malicious.

This reflects an important SOC principle:

> **Detection identifies activity requiring investigation; analysts establish whether that activity is malicious.**

---

# Testing

The project includes automated tests covering the detection engine and individual detection behaviors.

Current test result:

```text
13 passed
```

Run the complete test suite with:

```bash
python3 -m pytest -v
```

A successful run should report:

```text
13 passed
```

Python compilation can also be checked with:

```bash
python3 -m compileall -q parser detectors engine reporting dashboards main.py
```

---

# Reporting

The reporting component generates both JSON and HTML outputs.

### JSON

```text
reports/generated/windows_security_alerts.json
```

The JSON report is designed for machine-readable processing and future integration with other security tooling.

### HTML

```text
reports/generated/windows_security_report.html
```

The HTML report provides a human-readable representation of generated security alerts.

These generated reports are intentionally included in the repository as **portfolio demonstration artifacts**.

---

# Technologies

### Programming

* Python 3
* Object-oriented and modular Python design
* File parsing
* Structured data processing
* JSON serialization

### Cybersecurity

* Windows Security Events
* SOC detection concepts
* Authentication monitoring
* Account monitoring
* Privilege monitoring
* PowerShell monitoring
* Process monitoring
* Security log monitoring
* MITRE ATT&CK mapping
* False-positive analysis

### Engineering

* Modular architecture
* Automated testing
* Git version control
* Virtual environments
* JSON reporting
* HTML reporting

---

# MITRE ATT&CK Coverage

The project currently references several MITRE ATT&CK techniques relevant to Windows security monitoring.

| Technique | Detection Context                 |
| --------- | --------------------------------- |
| T1078     | Valid Accounts                    |
| T1098     | Account Manipulation              |
| T1110     | Brute Force                       |
| T1136     | Create Account                    |
| T1059     | Command and Scripting Interpreter |
| T1059.001 | PowerShell                        |
| T1070.001 | Clear Windows Event Logs          |

MITRE mappings are used to provide additional context for investigation and detection engineering.

---

# Installation

Clone the repository and enter the project directory:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd cybernova-windows-security-monitoring-lab
```

Create a Python virtual environment:

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

Install project dependencies:

```bash
pip install -r requirements.txt
```

Run the tests:

```bash
python3 -m pytest -v
```

---

# Running the Detection Lab

The sample Windows Security Event data can be processed through the project's parser and detection engine.

The laboratory is designed to operate entirely on the included synthetic dataset, making it suitable for development and demonstration without requiring access to a production Windows environment.

Generated reports can be found under:

```text
reports/generated/
```

---

# Security and Ethical Scope

This project is intended for:

* cybersecurity education
* blue-team training
* SOC analyst practice
* detection engineering
* defensive security research
* portfolio demonstration
* authorized laboratory environments

The included event data is synthetic and does not represent real customer, enterprise, or production security telemetry.

---

# Limitations

This is a **portfolio laboratory**, not a production SIEM or enterprise detection platform.

Current limitations include:

* Synthetic event data
* File-based event ingestion
* No live Windows Event Forwarding pipeline
* No production SIEM integration
* No real-time event streaming
* No centralized authentication
* No enterprise-scale alert management
* Limited correlation compared with commercial SIEM platforms

These limitations are intentional and provide opportunities for future development.

---

# Future Development

Potential improvements include:

* Live Windows Event Log ingestion
* Windows Event Forwarding support
* Sysmon event support
* More advanced event correlation
* Configurable detection thresholds
* YAML/JSON-based detection rules
* Alert deduplication
* Analyst case management
* Interactive security dashboards
* Risk scoring improvements
* Email or webhook alerting
* Elasticsearch/OpenSearch integration
* Splunk integration
* Sigma rule support
* Expanded MITRE ATT&CK coverage
* Detection performance benchmarking
* CI/CD security testing

---

# What This Project Demonstrates

This project demonstrates practical ability across both sides of a SOC/detection-engineering workflow:

### SOC Analyst Skills

* Security event analysis
* Alert interpretation
* Authentication investigation
* Privilege investigation
* Process analysis
* PowerShell investigation
* False-positive evaluation
* Risk prioritization
* Investigation recommendations

### Detection Engineering Skills

* Detection rule development
* Event correlation
* MITRE ATT&CK mapping
* Modular detection architecture
* Alert schema design
* Automated testing
* Security reporting
* Maintainable Python code

The project therefore serves as a practical demonstration of the workflow:

```text
Telemetry
   ↓
Parsing
   ↓
Detection
   ↓
Correlation
   ↓
Prioritization
   ↓
Investigation
   ↓
Reporting
```

---

# Author

**Ibrahim Mukhtar Saidu**

Aspiring Cybersecurity Analyst | Detection Engineering & SOC Security

**CYBERNOVA AI**

This project is part of my cybersecurity portfolio and demonstrates hands-on work in Python security automation, Windows security monitoring, SOC detection, and defensive security engineering.

---

## Disclaimer

This repository is intended for educational and defensive cybersecurity purposes.

All security events included in the laboratory are synthetic. The techniques and detection logic should be used only in systems and environments where you have appropriate authorization.

**Built for learning, detection engineering, and defensive security.**
