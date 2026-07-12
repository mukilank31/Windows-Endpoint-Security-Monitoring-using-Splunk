# Windows Endpoint Security Monitoring using Splunk

## 📌 Project Overview
This project demonstrates real-time **endpoint security monitoring** on a Windows 11 laptop using **Splunk Enterprise** and the **Splunk Universal Forwarder**. Unlike simulated/tutorial data, this project uses **live Windows Security Event Logs** generated directly from my own machine, ingested into Splunk for analysis, correlation, and alerting — replicating how a SOC Analyst monitors endpoint activity in a real enterprise environment.

## 🎯 Objective
- Collect and centralize Windows Security Event Logs from an endpoint into Splunk
- Build detection use cases around authentication, privilege usage, and credential access events
- Visualize security-relevant activity through a custom SOC dashboard
- Map observed behavior to the **MITRE ATT&CK framework**
- Configure a real-time alert for suspicious activity

## 🛠️ Tools & Technologies
| Tool | Purpose |
|---|---|
| Splunk Enterprise | SIEM platform for indexing, searching, and visualizing logs |
| Splunk Universal Forwarder | Agent installed on the Windows endpoint to forward event logs to Splunk |
| Windows Event Viewer | Native source of Security Event Logs (Security channel) |
| SPL (Search Processing Language) | Writing detection queries and building dashboard panels |

## 📊 Data Source
- **Source:** Live Windows Security Event Logs (`WinEventLog:Security`)
- **Collection method:** Splunk Universal Forwarder installed on personal Windows 11 laptop, forwarding logs to Splunk Enterprise (indexer running on `localhost:8000`)
- **Total events indexed:** 3,399
- **Unique EventCodes observed:** 14
- **Time range analyzed:** 2026-06-30 to 2026-07-01

## 🖥️ Dashboard: Windows Endpoint Security Dashboard

![Windows Endpoint Security Dashboard - Page 1](images/dashboard-1.png)
![Windows Endpoint Security Dashboard - Page 2](images/dashboard-2.png)

The dashboard has 4 panels, each built as a standalone SPL search:

### 1️⃣ Security EventCode Summary
Breaks down all 3,399 events by EventCode to give a quick volume overview of what kind of activity dominates the endpoint.

| EventCode | Meaning | Count |
|---|---|---|
| 5379 | Credential Manager credential read | 2928 |
| 4624 | Successful logon | 120 |
| 4672 | Special privileges assigned to new logon | 116 |
| 4798 | User's local group membership enumerated | 69 |
| 5058 | Key file operation (crypto) | 63 |
| 5061 | Cryptographic operation | 62 |
| 4799 | Security-enabled local group membership enumerated | 8 |
| 4797 | Attempt to query account with blank password | 7 |
| 4634 | Logoff | 6 |
| 4625 | Failed logon | 5 |
| 4648 | Logon using explicit credentials | 5 |
| 5382 | System audit policy change (unsuccessful) | 4 |
| 4616 | System time changed | 3 |
| 5059 | Key migration operation | 3 |

**SPL used:**
```spl
index=* sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort -count
```

### 2️⃣ Failed Logon Attempts
Filters specifically for **EventCode 4625** (failed logon) to surface potential brute-force or misconfiguration activity — a core SOC triage panel.

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4625
| table _time, Account_Name, Failure_Reason, Logon_Type
| sort -_time
```

**Observation:** All 5 failed logons were tied to the `mukil` account with the reason *"Unknown user name or bad password"* and Logon_Type 2 (interactive logon), consistent with local password entry errors rather than an external attack.

### 3️⃣ Privilege Usage by Account
Tracks **EventCode 4672** (special privileges assigned at logon) grouped by account — used to spot unexpected privilege escalation.

```spl
index=* sourcetype="WinEventLog:Security" EventCode=4672
| stats count by Account_Name
| sort -count
```

**Observation:** `SYSTEM` accounted for 111 of 116 privileged logons (expected — normal OS/service behavior), with only 4 tied to the local `mukil` account and 1 to `Splunkd`, showing no abnormal privilege grants.

### 4️⃣ Credential Access Pattern (Timeline)
Tracks **EventCode 5379** (Credential Manager reads) over time in hourly buckets — this is the highest-volume EventCode and maps directly to a MITRE ATT&CK technique (below).

```spl
index=* sourcetype="WinEventLog:Security" EventCode=5379
| timechart span=1h count
```

**Observation:** Two sharp spikes — 964 events at 13:30 and 1,397 events at 11:30 on consecutive days — stand out against an otherwise near-zero baseline. This kind of burst pattern is exactly what a SOC Analyst would pivot on to check what process/application triggered mass credential reads at that time.

## 🚨 Alert Configured
A real-time alert was configured to trigger when **EventCode 4625 (failed logon) exceeds a threshold within a rolling window**, simulating brute-force detection logic used in production SOC environments.

## 🎯 MITRE ATT&CK Mapping
| EventCode | Technique | Technique ID | Tactic |
|---|---|---|---|
| 5379 | Credentials from Password Stores: Windows Credential Manager | **T1555.004** | Credential Access |

The dominant volume of EventCode 5379 (2,928 of 3,399 total events — ~86%) makes Credential Access the primary tactic observed on this endpoint during the monitoring window.

## ✅ Key Takeaways
- Centralizing endpoint logs into a SIEM turns thousands of scattered raw events into a handful of actionable panels
- High-frequency EventCodes (like 5379) aren't automatically malicious — but timeline analysis reveals *when* the activity spiked, which is the real starting point for investigation
- Correlating failed logons with account + logon type quickly separates "user typo" noise from genuine brute-force patterns
- Mapping raw Windows EventCodes to MITRE ATT&CK gives detections a common language used across real SOC teams

## 🔗 Related Project
This is Project 2 in my Splunk SOC portfolio. Project 1 — **E-Commerce Web Security Monitoring** (Buttercup Games dataset) — covers web application attack detection using the same Splunk stack.

---
**Author:** Mukilan K
**Tools:** Splunk Enterprise, Splunk Universal Forwarder, Windows Event Viewer
**Repository:** `splunk-security-projects`
