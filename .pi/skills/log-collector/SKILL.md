---
name: log-collector
description: Optimized Host-based forensic collection using Grep-First strategy.
parameters:
  dest_ip:
    type: string
    description: "The victim IP address to investigate."
    required: true
  target_timestamp:
    type: string
    description: "Pivot timestamp in ISO/Splunk format."
    required: true
  window:
    type: integer
    description: "Search radius in minutes (+/-)."
    default: 5
  input_file:
    type: string
    description: "Path to Sysmon NDJSON logs."
    default: "./.pi/data/sysmon_logs_botsv1.json"
  output_file:
    type: string
    description: "Path to save result JSON."
    default: "./.pi/output/log_collector_result.json"
outputs:
  analysis_summary:
    type: string
    description: "Human-readable summary of suspicious findings."
  risk_level:
    type: string
    description: "Final risk assessment (high/low)."
---

# Log Collector Skill

## Execution Syntax
```bash
python3 ./.pi/skills/log-collector/collect_logs.py \
  --dest-ip "192.168.250.70" \
  --target-timestamp "2016-08-10T15:36:48Z" \
  --window 60 \
  --input-file "./.pi/data/sysmon_logs_botsv1.json"
```

## Operational Constraints
- **Default Paths:** Now points to `./.pi/data/sysmon_logs_botsv1.json`.
