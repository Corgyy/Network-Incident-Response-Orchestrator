---
name: log-collector
description: Analyzes Sysmon logs from BOTSv1 data to extract host-based evidence such as process creation, suspicious command lines, executable artifacts, hashes, and process-level network connections.
parameters:
  dest_ip:
    type: string
    description: The victim destination IP address to investigate.
  target_timestamp:
    type: string
    description: The timestamp of the alert in ISO format.
  input_file:
    type: string
    description: Path to the sysmon_logs_botsv1.json file.
    default: ".pi/data/sysmon_logs_botsv1.json"
  alert_file:
    type: string
    description: Optional path to the alerts_trigger_botsv1.json file. Used when dest_ip and target_timestamp are not provided manually.
    default: ".pi/data/alerts_trigger_botsv1.json"
  window:
    type: integer
    description: Time window in minutes around the alert timestamp.
    default: 5
  output_file:
    type: string
    description: Path to save the full Log Collector JSON result.
    default: ".pi/output/log_collector_result.json"
outputs:
  suspicious_processes:
    type: array
    description: Suspicious Sysmon Event ID 1 process creation records.
  suspicious_commands:
    type: array
    description: Suspicious command lines detected from process creation events.
  network_connections:
    type: array
    description: Victim-related Sysmon Event ID 3 network connection records.
  executable_evidence:
    type: array
    description: Executable artifacts discovered in suspicious or interesting host paths.
  hash_evidence:
    type: array
    description: Hash values extracted from Sysmon process creation events.
  analysis_summary:
    type: string
    description: A human-readable summary of host-based activity.
---

# Log Collector Skill

This skill processes Sysmon logs from Splunk BOTSv1 to identify host-based evidence related to an incident.

## Capabilities

- **Time-Windowed Filtering:** Filters Sysmon events within a configurable time window around the alert timestamp.
- **Process Creation Analysis:** Extracts Sysmon Event ID 1 records.
- **Network Connection Analysis:** Extracts Sysmon Event ID 3 records related to the victim IP.
- **Suspicious Command Detection:** Detects PowerShell, cmd.exe, certutil, rundll32, regsvr32, wscript, schtasks, wmic, and other suspicious command patterns.
- **Executable Evidence Extraction:** Finds suspicious executable artifacts such as web-root or user-directory executables.
- **Hash Extraction:** Extracts MD5, SHA1, SHA256, and IMPHASH values when available.
- **JSON Output:** Saves the full analysis result to a JSON file for downstream MITRE mapping and IR reporting.

## Usage

Alert-based analysis:

```bash
python .pi/skills/log-collector/collect_logs.py --input-file .pi/data/sysmon_logs_botsv1.json --alert-file .pi/data/alerts_trigger_botsv1.json --window 5 --output-file .pi/output/log_collector_result.json