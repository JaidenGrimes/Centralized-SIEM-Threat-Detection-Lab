# Centralized SIEM & Threat Detection Lab

**Splunk Enterprise | Sysmon | Windows 11 | Ubuntu Linux**

## Architecture Overview

- **SIEM Server:** Splunk Enterprise hosted on Ubuntu Linux (`192.168.10.4`)
- **Target Endpoint:** Windows 11 Enterprise (`WIN11-CLI`) running Microsoft Sysmon and Splunk Universal Forwarder
- **Telemetry Pipeline:** Sysmon Event IDs 1, 3, 11 and Windows Security Audit logs ingested into centralized indices for threat hunting

## Key Capabilities Developed

- **Telemetry Collection:** Configured Microsoft Sysmon with an advanced security configuration to capture process creation, network connections, and file modifications
- **Detection Engineering:** Engineered custom Splunk Processing Language (SPL) detection rules to identify post-exploitation activity, command-line obfuscation, and internal reconnaissance
- **SOC Monitoring:** Designed operational dashboard architecture to aggregate and visualize critical endpoint alerts

## Detection Engineering & SPL Queries

### 1. Encoded PowerShell Execution Detection

Detects encoded PowerShell commands that may be used to obfuscate malicious payloads.

```spl
index=main Image="*\\powershell.exe" (CommandLine="*-e *" OR CommandLine="*-enc*")
| table _time host User Image CommandLine
```

### 2. Active Directory Domain Reconnaissance

Detects native Windows enumeration commands such as `net group` and `net user /domain` used during internal discovery.

```spl
index=main (CommandLine="*net user /domain*" OR CommandLine="*net group*")
| table _time host User Image CommandLine
```

### 3. Credential Access & Brute-Force Detection

Monitors Windows Security Event ID `4625` for spikes in failed logon attempts.

```spl
index=main EventCode=4625
| stats count by TargetUserName, WorkstationName, src_ip
| where count > 3
```

## Operational Dashboard & Workflow

**Dashboard:** SOC Threat Detection & Endpoint Operations

### Panels

- **Sysmon Process Creation** – Monitors suspicious parent-child process chains
- **Failed Authentication Spikes** – Tracks Event ID 4625 for brute-force patterns
- **Obfuscated Script Execution** – Flags encoded command-line execution

## Skills Demonstrated

`Splunk` `SPL` `Sysmon` `SIEM` `Threat Detection` `Threat Hunting` `Windows Security` `SOC Monitoring` `Detection Engineering`
