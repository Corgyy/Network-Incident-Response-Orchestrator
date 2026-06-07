---
name: network-protocol-analyzer
description: High-performance network flow feature extraction using Grep-First filtering.
parameters:
  src_ip:
    type: string
    description: "The source IP to analyze (usually the attacker)."
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
    description: "Path to network stream logs."
    default: "./.pi/data/network_streams_botsv1.json"
  output_file:
    type: string
    description: "Path to save network result JSON."
    default: "./.pi/output/network_analyzer_result.json"
outputs:
  feature_vector:
    type: object
    description: "Aggregated flow metrics (bytes, packets, ratios)."
  analysis_summary:
    type: string
    description: "Natural language summary of network behavior."
---

# Network Protocol Analyzer Skill

## Execution Syntax
```bash
python3 ./.pi/skills/network-analyzer/analyze_network.py \
  --src-ip "40.80.148.42" \
  --target-timestamp "2016-08-10T15:36:48Z" \
  --window 55 \
  --output-file "./.pi/output/network_analyzer_result.json"
```

## Operational Constraints
- **Relative Paths:** Always use relative paths starting with `./`.
