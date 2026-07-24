
# threat-hunt-hidden-directive

> A full incident reconstruction from real cyber range telemetry — conducted on the LOG(N) Pacific Cyber Range by SancLogic.

---

## Overview

| Field | Detail |
|---|---|
| **Case Reference** | GF-INC-2026-0704 |
| **Incident Name** | Hidden Directive |
| **Organisation** | Greenfield Logistics (simulated) |
| **Incident Date** | 4 July 2026 |
| **Report Date** | 2026-07-23 |
| **Analyst** | Chris Mondejar |
| **Platform** | LOG(N) Pacific Cyber Range // SancLogic |
| **Severity** | Critical |

---

## What This Is

This repository contains my full incident report for **GF-INC-2026-0704 (Hidden Directive)** — a graded threat hunt investigation conducted on the LOG(N) Pacific Cyber Range. The exercise involved reconstructing a real intrusion from live telemetry and recovered artefacts, with no planted flags and no walkthrough.

The report was produced as a **solo submission** as part of my cybersecurity internship at Log(N) Pacific, where I work as a Cyber Security Support Analyst. It demonstrates hands-on threat hunting, incident reconstruction, and technical reporting skills built during that programme.

---

## The Scenario

Three Greenfield Logistics hosts were compromised on 4 July 2026:

- **GF-WS01** — user workstation (primary entry point)
- **GF-SRV01** — file server hosting Finance share (lateral pivot)
- **GF-DC01** — domain controller (full domain compromise)

The investigation was driven by three questions from the security lead:

> *"How they got in. How far they went. What they took."*

---

## Key Findings

- **Initial access** via RDP (sancadmin) + indirect prompt injection against Greenfield's AI page-summariser tool
- **AdaptixC2** beacon deployed at 10:15:32 UTC via python.exe spawning loader.ps1 — AMSI bypassed, shellcode XOR-decoded and injected in-memory
- **C2 channel** routed through Cloudflare CDN (`cdn.cloud-endpoint.net` → `172.67.174.46`) — 400+ HTTPS beacons over ~7 hours
- **Credential access** via LSASS memory dump (Explorer.exe injected, GrantedAccess 0x1010)
- **Lateral movement** to GF-SRV01 (t.harris) and GF-DC01 (d.williams) using Impacket and RemCom
- **Domain compromise** — Golden Ticket attack, LSA secrets theft, full AD enumeration
- **AdminSDHolder abuse** — svc_backup granted GenericAll across all privileged AD groups (persistent domain backdoor)
- **Five accounts compromised**: sancadmin, d.williams, t.harris, svc_backup, m.smith

---

## Investigation Methodology

- **Two SIEM sources**: Microsoft Sentinel (LAW-SilentCorridor, ASIM tables) + Microsoft Defender XDR (LAW-Cyber-Range, MDE Device* tables)
- **Five triage artefacts**: static analysis of blog_lure.html, loader.ps1, shellcode_encoded.bin, gfupdater.exe, hOQjiirI.exe — all hashes verified against case manifest
- **30+ KQL queries** across WindowsProcess_CL, WindowsAuth_CL, WindowsNetwork_CL, WindowsDNS_CL, WindowsProcessAccess_CL, WindowsService_CL, DeviceProcessEvents, DeviceFileEvents, AlertInfo/AlertEvidence
- **MITRE ATT&CK mapped** throughout — 32 techniques across 10 tactics

---

## MITRE ATT&CK Summary

| Tactic | Key Techniques |
|---|---|
| Initial Access | T1021.001 (RDP), T1078 (Valid Accounts), T1566 (Phishing/AI lure) |
| Execution | T1204 (AI agent abuse), T1059.001 (PowerShell), T1543.003 (Windows Service) |
| Persistence | T1053.005 (Scheduled Task), T1547.001 (Run Key), T1098 (AdminSDHolder), T1219 (AnyDesk) |
| Defence Evasion | T1562.001 (AMSI bypass), T1055 (Process Injection), T1090.002 (CDN Proxy), T1218.001 (certutil) |
| Credential Access | T1003.001 (LSASS), T1003.004 (LSA Secrets), T1558.001 (Golden Ticket) |
| Discovery | T1087.002, T1069, T1018 (Full AD enumeration) |
| Lateral Movement | T1021.001 (RDP), T1021.002 (SMB/RemCom), T1570 (Lateral Tool Transfer) |
| C&C | T1071.001 (HTTPS), T1573 (Encrypted Channel), T1090.002 (Cloudflare proxy) |
| Collection | T1039 (Network Share), T1074 (Data Staged) |
| Impact | T1558.001 (Golden Ticket — domain-wide) |

---

## Indicators of Compromise

| Type | Indicator |
|---|---|
| Domain | `cdn.cloud-endpoint.net` |
| Domain | `api.cloud-endpoint.net` |
| IP | `172.67.174.46` (Cloudflare C2 proxy) |
| IP | `10.1.0.120` (attacker source — unmanaged host) |
| SHA-256 | `ff7f87ae...5199` — blog_lure.html |
| SHA-256 | `93164086...7583` — loader.ps1 |
| SHA-256 | `4713e5e9...4af9` — gfupdater.exe |
| SHA-256 | `3c2fe308...e7f71` — hOQjiirI.exe (RemCom) |
| File | `C:\ProgramData\GFUpdater\gfupdater.exe` |
| Service | `JWbf` (RemCom service on GF-DC01) |
| Account | `svc_backup` (attacker-planted domain backdoor) |

---

## Files in This Repository

| File | Description |
|---|---|
| `GF-INC-2026-0704_Hidden-Directive_Incident-Report.md` | Full incident report — 12 sections, MITRE mapped, detection pack included |
| `README.md` | This file |

---

## Detection Pack

Four KQL detection rules are included in Section 11 of the report, covering techniques that did not alert during the incident:

1. **Scripting engine spawning hidden PowerShell download cradle** (T1059.001, T1204, T1566)
2. **Suspicious LSASS memory access** — GrantedAccess 0x1010/0x1038/0x1fffff (T1003.001)
3. **AdminSDHolder ACL modification** (T1098) — fires immediately, no suppression recommended
4. **certutil used as download cradle** (T1218.001, T1105)

---

## About Me

I'm an Electrical & Mechanical Maintenance Engineer transitioning into cybersecurity, currently completing an internship as a Cyber Security Support Analyst at Log(N) Pacific. My background in industrial and maritime engineering gives me a strong OT/ICS security perspective alongside the SOC skills I'm building through this programme.

This investigation was completed as part of the Hidden Directive graded exercise (GF-INC-2026-0704), submitted to SancLogic on 2026-07-23.

---

## Acknowledgements

- **Mohammed A** — Hunt Lead, SancLogic — for designing Hidden Directive
- **LOG(N) Pacific Cyber Range** — the platform and team behind the exercise
- **SancLogic** — for building and running the Greenfield estate

---

*This repository documents a simulated incident conducted on the LOG(N) Pacific Cyber Range for training and assessment purposes. All host names, accounts, and organisation details are fictional.*
