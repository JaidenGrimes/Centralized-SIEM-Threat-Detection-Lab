# Centralized SIEM & Threat Detection Lab

## Overview
Deploys a centralized SIEM environment using Splunk Enterprise, Microsoft Sysmon, and Splunk Universal Forwarder. This lab focuses on endpoint telemetry collection, SPL-based detection engineering, threat hunting, and SOC monitoring using Windows security and Sysmon event data.

## Environment & Prerequisites
- **SIEM Platform:** Splunk Enterprise
- **SIEM Server:** Ubuntu Linux (`192.168.10.4`)
- **Client Endpoint:** Windows 11 Enterprise (`WIN11-CLI`)
- **Endpoint Telemetry:** Microsoft Sysmon
- **Log Forwarding:** Splunk Universal Forwarder
- **Data Sources:** Sysmon Event IDs `1`, `3`, `11` and Windows Security Audit logs

---

## Deployment & Configuration Steps

### 1. Endpoint Telemetry Collection
- Configured Microsoft Sysmon on the Windows 11 endpoint.
- Collected process creation, network connection, and file modification telemetry.
- Forwarded endpoint event logs to the centralized Splunk Enterprise server using Splunk Universal Forwarder.

### 2. Splunk SIEM Integration
- Ingested Sysmon and Windows Security Audit logs into centralized Splunk indices.
- Used collected endpoint telemetry for security monitoring and threat hunting.

### 3. Encoded PowerShell Execution Detection
Created an SPL detection query to identify encoded PowerShell commands that may indicate command-line obfuscation.

```spl
index=main Image="*\\powershell.exe" (CommandLine="*-e *" OR CommandLine="*-enc*")
| table _time host User Image CommandLine
```

### 4. Active Directory Domain Reconnaissance Detection
Created an SPL detection query for native Windows enumeration commands such as `net user /domain` and `net group`.

```spl
index=main (CommandLine="*net user /domain*" OR CommandLine="*net group*")
| table _time host Use* Image CommandLine
```

### 5. Failed Authentication & Brute-Force Detection

Monitored Windows Security Event ID `4625` and Event ID `5379` using XML regex parsing to identify spikes in failed authentication and credential access attempts.

```spl
index=main sourcetype="XmlWinEventLog:Security" 
| rex field=_raw "<EventID>(?<EventCode>\d+)</EventID>"
| search EventCode=4625 OR EventCode=5379
| rex field=_raw "<Data Name="TargetUserName">(?<TargetUserName>[^<]+)</Data>"
| stats count by TargetUserName host EventCode
| sort - count
```

### 6. SOC Threat Detection Dashboard

Designed the **SOC Threat Detection & Endpoint Operations** dashboard to centralize endpoint security monitoring.

Dashboard panels include:
- **Sysmon Process Creation** - Monitors suspicious parent-child process chains.
- **Failed Authentication Spikes** - Tracks Event ID `4625` for brute-force patterns.
- **Obfuscated Script Execution** - Flags encoded command-line execution.

---

## Key Takeaways

- **SIEM & Log Management:** Centralized Windows endpoint telemetry using Splunk Enterprise and Splunk Universal Forwarder.
- **Detection Engineering:** Developed custom SPL detection queries for suspicious PowerShell activity, reconnaissance, and failed authentication attempts.
- **Endpoint Visibility:** Used Sysmon telemetry to monitor process creation, network connections, and file modifications.
- **SOC Monitoring:** Built a centralized dashboard for monitoring endpoint security activity and detection events.
