# windows-soc-endpoint-monitoring-lab
A practical Windows SOC home lab for endpoint monitoring, Sysmon telemetry, PowerShell investigation, process analysis, and evidence-based threat detection.

## Objective

The objective of this project was to build and investigate a controlled Windows endpoint monitoring environment using Sysmon.

The investigation focused on understanding:

- Windows endpoint telemetry
- Sysmon process creation events
- Parent-child process relationships
- PowerShell activity
- Command-line analysis
- File activity correlation
- Network activity correlation
- Registry and persistence checks
- Evidence-based SOC classification

## Lab Environment

| Component | Details |
|---|---|
| Endpoint | Windows 11 VM |
| Hostname | SOCWIN11-01 |
| User | socwi |
| Telemetry | Sysmon |
| Primary Event | Sysmon Event ID 1 |
| Investigation Type | Controlled SOC investigation |

## Investigation Scenario

A medium-severity SOC alert was generated for suspicious PowerShell activity on the Windows endpoint.

The initial telemetry showed Microsoft Word launching PowerShell:

WINWORD.EXE → powershell.exe

The PowerShell command line contained:

- `-NoProfile`
- `-ExecutionPolicy Bypass`
- `-EncodedCommand`

These characteristics were considered suspicious and required further investigation.

The presence of suspicious indicators alone was not considered sufficient evidence to classify the activity as malicious.

## Investigation Methodology

The investigation followed a correlation-based SOC workflow:

1. Establish the alert timeframe.
2. Identify relevant process creation events.
3. Build the parent-child process relationship.
4. Examine the PowerShell command line.
5. Investigate subsequent child processes.
6. Check for suspicious file activity.
7. Check for network connections.
8. Check for registry and persistence activity.
9. Decode and analyze the PowerShell command.
10. Classify the activity based on the available evidence.

## Process Investigation

The observed process chain was:

WINWORD.EXE
↓
powershell.exe
↓
cmd.exe
↓
whoami.exe

The PowerShell process was launched by Microsoft Word.

PowerShell subsequently launched `cmd.exe`, which launched `whoami.exe`.

The `whoami` command was used to identify the logged-in user.

## Command-Line Investigation

The PowerShell command line contained:

`-ExecutionPolicy Bypass`

and:

`-EncodedCommand`

These options increased the suspicion level of the event because they can be associated with PowerShell execution techniques used during malicious activity.

However, the presence of these options does not independently prove malicious intent.

The encoded command was decoded during the investigation and resolved to:

`whoami`

## Correlation Results

### Process Activity

PowerShell spawned `cmd.exe`, which spawned `whoami.exe`.

No additional malicious process behavior was identified.

### File Activity

No suspicious file creation or modification associated with the investigated PowerShell activity was identified.

### Network Activity

No suspicious network connection associated with the investigated activity was identified.

### Registry / Persistence

No registry or persistence activity associated with the investigated PowerShell activity was identified.

## Evidence Summary

| Evidence | Finding |
|---|---|
| Word → PowerShell | Suspicious |
| ExecutionPolicy Bypass | Suspicious |
| EncodedCommand | Suspicious |
| Encoded command content | `whoami` |
| PowerShell child process | `cmd.exe` |
| cmd child process | `whoami.exe` |
| Suspicious file activity | Not identified |
| Suspicious network activity | Not identified |
| Persistence activity | Not identified |

## Final Classification

**Benign / False Positive**

The activity initially appeared suspicious because Microsoft Word launched PowerShell using `-ExecutionPolicy Bypass` and `-EncodedCommand`.

Further investigation showed that the encoded command decoded to `whoami`.

No suspicious file activity, network connections, or persistence mechanisms were identified.

Based on the available telemetry, no evidence of malicious activity was identified.

## SOC Analyst Lesson

This investigation demonstrated an important SOC principle:

> Suspicious does not automatically mean malicious.

An analyst should not classify an event based on a single indicator.

The appropriate workflow is:

Detection → Investigation → Correlation → Evidence Analysis → Classification

The final classification should be based on the totality of available evidence.

## Skills Demonstrated

- Windows endpoint monitoring
- Sysmon deployment
- Sysmon Event ID 1 analysis
- Parent-child process analysis
- PowerShell investigation
- Command-line analysis
- Process-tree reconstruction
- File activity correlation
- Network activity correlation
- Registry/persistence investigation
- Evidence-based classification
- False-positive analysis
- SOC investigation methodology
