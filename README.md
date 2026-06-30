# SSH Brute Force Detection Lab

A SOC detection lab simulating and detecting SSH brute force attacks using Splunk Enterprise, built on a Kali Linux home lab.

## Overview

This project demonstrates an end-to-end detection pipeline: attack simulation → log ingestion → SPL detection logic → real-time alerting. It replicates a real-world brute force scenario an SOC L1 analyst would investigate.

## Architecture


<img width="1920" height="1020" alt="Screenshot 2026-06-30 152957" src="https://github.com/user-attachments/assets/bfeef89f-a1aa-47b2-bc49-f0805536dd47" />



Kali Linux (Attacker + Target)
├── Hydra → SSH Brute Force Attack
├── OpenSSH Server (target service)
├── rsyslog → auth.log generation
└── Splunk Enterprise
├── Data Ingestion (/var/log/auth.log)
├── SPL Detection Query
└── Scheduled Alert

## Tools Used

- **Splunk Enterprise 10.4.0** — SIEM platform
- **Kali Linux** — attack and target environment
- **Hydra** — brute force attack simulation
- **OpenSSH** — target authentication service
- **rsyslog** — log generation and forwarding

## Attack Simulation

Simulated a brute force attack against the local SSH service using Hydra with the rockyou.txt wordlist:

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1 -t 4 -V
```

This generated authentic `auth.log` events including failed password attempts, PAM authentication failures, and connection terminations due to excessive retries.

## Detection Logic

### Step 1 — Identify all failed login attempts

```spl
index=main source="/var/log/auth.log"
| search "Failed password"
| rex field=_raw "Failed password for (?<user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as failed_attempts by src_ip, user
| sort -failed_attempts
```

### Step 2 — Threshold-based brute force detection

Flags any source IP/user combination exceeding 5 failed attempts within a 1-minute window — a standard brute force detection threshold.

```spl
index=main source="/var/log/auth.log"
| search "Failed password"
| rex field=_raw "Failed password for (?<user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| bucket _time span=1m
| stats count as failed_attempts by _time, src_ip, user
| where failed_attempts >= 5
| sort -failed_attempts
```

## Alert Configuration

| Setting | Value |
|---|---|
| Alert Name | SSH Brute Force Detection |
| Type | Scheduled, hourly |
| Trigger Condition | Number of results > 0 |
| Action | Add to Triggered Alerts |

## Results

- 48+ failed login events captured and correlated
- All attempts traced to source IP `127.0.0.1` targeting user `root`
- Detection query successfully isolated brute force pattern from background noise
- Alert configured for ongoing monitoring

## Dashboard

Built a SOC Monitoring Dashboard with the following panels:
- Total events (24h)
- Total errors/failures (24h)
- Top log sources (bar chart)
- Errors by source (pie chart)
- SSH brute force attempts over time (line chart)

## Skills Demonstrated

- SPL (Search Processing Language) query development
- Regex field extraction (`rex`)
- Time-based correlation (`bucket`, `timechart`)
- Threshold-based anomaly detection
- Splunk alerting and scheduling
- Linux log management (rsyslog, auth.log)
- Attack simulation and detection engineering

## Author

Arsalan — SOC L1 Analyst | Dubai, UAE
