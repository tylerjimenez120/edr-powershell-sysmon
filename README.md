
# Experimental Windows EDR — PowerShell + Sysmon

A Windows endpoint monitoring and controlled-response prototype built with Sysmon telemetry and PowerShell.

The project implements event acquisition, behavioral detection, ProcessGuid-based correlation, weighted risk scoring, and controlled response actions.

**Status:** Experimental prototype. Not a production EDR or antivirus replacement.

## Architecture

```text
Windows Activity
       |
       v
Sysmon Service
       |
       v
Microsoft-Windows-Sysmon/Operational
       |
       v
PowerShell Event Acquisition
       |
       v
Rule Evaluation
       |
       v
ProcessGuid Correlation
       |
       v
Risk Scoring
       |
       v
Response Policy
       |
       +--> Alert / Logging
       |
       +--> Lab Containment
```

## Technical Implementation

### Telemetry

The monitoring engine processes Sysmon events:

| Event ID | Description |
|----------|-------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 10 | Process Access |
| 11 | File Creation |

### Event Correlation

Events are correlated using `ProcessGuid` within an approximately 60-second window.

The correlation engine evaluates combinations of process execution, file creation, and network activity.

### Risk Scoring

Weighted scoring is applied to individual and correlated signals.

| Signal | Score |
|--------|-------|
| Process execution | +20 |
| File creation | +25 |
| Network connection | +30 |
| Process + Network correlation | +10 |
| Three-signal correlation | +15 |

Maximum score: 100.

### Response Engine

Supported mechanisms include:

- Alert generation and event logging
- DryRun evaluation
- Controlled process termination
- Windows Firewall rule creation
- File quarantine
- Action verification
- Rollback of recorded lab actions

Active containment is restricted to a predefined laboratory scenario.

## Laboratory Validation

A controlled test generated:

```text
ProcessCreate
      |
FileCreate
      |
NetworkConnect
      |
RiskScore: 100
RiskLevel: HIGH
```

Observed response results:

```text
Firewall    : SUCCESS
Quarantine  : SUCCESS
Containment : SUCCESS
```

A subsequent Sysmon process event was also detected after several hours of DryRun monitoring.

These observations validate the tested scenarios, not comprehensive malware detection.

## Requirements

- Windows
- Windows PowerShell 5.1
- Sysmon installed and configured
- Administrator privileges for the required operations

Sysmon binaries are distributed separately by Microsoft.

## Usage

Start the monitoring engine:

```powershell
.\edr-monitor-v2.ps1
```

DryRun is the default execution mode.

For controlled laboratory validation, review the test script before running:

```powershell
.\test2.ps1
```

Active containment must only be used in an authorized laboratory environment. Firewall rules may persist until explicit rollback.

## Limitations

- Rule-based detection
- Sysmon-dependent telemetry
- Possible false positives and false negatives
- No guaranteed event recovery after monitoring interruptions
- No validated high-load performance benchmarks
- No comprehensive evasion resistance
- No general-purpose production containment

## Next Stage

A separate native C++ implementation will explore ETW-based acquisition, asynchronous event processing, bounded queues, concurrency control, and separation of acquisition, detection, and response.

## Disclaimer

This project is intended for educational, research, and controlled laboratory use. Keep existing endpoint security protections enabled.
