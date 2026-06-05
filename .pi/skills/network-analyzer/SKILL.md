---
name: network-protocol-analyzer
description: Analyzes multi-protocol network streams from BOTSv1 data to extract feature vectors for incident classification.
parameters:
  src_ip:
    type: string
    description: The source IP address to investigate.
  target_timestamp:
    type: string
    description: The timestamp of the alert in ISO format.
  input_file:
    type: string
    description: Path to the network_streams_botsv1.json file.
    default: "topic9-ir-orchestrator/.pi/data/network_streams_botsv1.json"
outputs:
  feature_vector:
    type: object
    description: A dictionary of aggregated network features (volume, timing, protocols).
  analysis_summary:
    type: string
    description: A human-readable summary of the network behavior.
---

# Network Protocol Analyzer Skill

This skill processes raw network stream data from Splunk BOTSv1 (exported as JSON) to identify patterns of attack.

## Capabilities
- **Time-Windowed Filtering:** Filters records within ±5 minutes of the alert.
- **Protocol Aggregation:** Groups data by application (HTTP, DNS, TCP, etc.).
- **Feature Engineering:** Computes throughput, packet counts, and flow duration.
- **Exfiltration Detection:** Analyzes data volume ratios (bytes_out vs bytes_in).

## Usage
The skill is called by the `network-analyzer-agent` during Stage 1 of the IR pipeline.
