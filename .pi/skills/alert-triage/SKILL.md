---
name: alert-triage-agent
description: Orchestration Step 0 - Analyzes multi-source alerts to establish incident context and timelines.
parameters:
  ioc:
    type: string
    description: "The indicator of compromise (IP, Domain, Signature, or Filename) to triage."
    required: true
  alert_file:
    type: string
    description: "Path to the Suricata IDS alerts file."
    default: "./.pi/data/alerts_trigger_botsv1.json"
  sysmon_file:
    type: string
    description: "Path to the Sysmon host logs file."
    default: "./.pi/data/sysmon_logs_botsv1.json"
outputs:
  triage_context:
    type: object
    description: "Calculated orchestration context including inferred roles, timeline, and next-step arguments."
---

# Alert Triage Skill (Optimized)

## Overview & Capabilities
This skill serves as the **primary orchestrator (Step 0)**. 
- **Time Drift Detection:** Automatically compares alert timestamps with host log ranges and issues critical warnings if dates do not match.
- **Role Inference:** Determines Attacker vs. Victim roles.
- **Dynamic Bounding:** Calculates precise investigation windows.

## Execution Syntax
```bash
python3 ./.pi/skills/alert-triage/triage_alerts.py --ioc "40.80.148.42"
```

## Operational Constraints
- **Standardized Paths:** Defaults to `./.pi/data/` structure.
- **Sanity Checks:** If a `CRITICAL TIME MISMATCH` warning is returned, the agent must inform the user that log collection for this date will fail.
