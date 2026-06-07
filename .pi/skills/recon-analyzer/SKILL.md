---
name: recon-analyzer
description: OSINT Intelligence - Automated reputation lookup for IP, Domain, or Hash via VirusTotal.
parameters:
  ioc:
    type: string
    description: "The Indicator of Compromise (IP address, Domain name, or File Hash)."
    required: true
  output:
    type: string
    description: "Path to save OSINT result JSON."
    required: true
  vt_key:
    type: string
    description: "VirusTotal API Key."
    default: "00fa140d20875f2330e3065f67865979254a1bd1854c557ca7caf495838b4230"
outputs:
  ioc_type:
    type: string
    description: "Detected type (ip, domain, or hash)."
  malicious_engines:
    type: integer
    description: "Count of vendors flagging the IOC as malicious."
  is_malicious:
    type: boolean
    description: "Final Boolean verdict."
---

# Recon Analyzer Skill (Synchronous)

## Overview & Capabilities
Provides external context to internal alerts using the **VirusTotal V3 API**.
- **Auto-Detection Logic:** Uses robust Regex to distinguish between IPv4, Domains, and MD5/SHA256 hashes.
- **Global Intelligence:** Fetches reputation scores and malicious detection stats from 70+ security vendors.
- **Environment Compatibility:** Uses the `requests` library for synchronous execution without additional dependencies.

## Execution Syntax
```bash
python3 ./.pi/skills/recon-analyzer/analyze_recon.py \
  --ioc "EC78C938D8453739CA2A370B9C275971EC46CAF6E479DE2B2D04E97CC47FA45D" \
  --output "./.pi/output/recon_hash_result.json"
```

## Output Schema
```json
{
  "ioc": "...",
  "ioc_type": "hash",
  "malicious_engines": 66,
  "vt_reputation_score": -15,
  "is_malicious": true
}
```

## Operational Constraints
- **CRITICAL WARNING:** A result of 0 malicious engines does **NOT** mean the entity is safe. Many attackers use fresh infrastructure. You are **MANDATED** to continue the investigation into local logs (Triage & Collection) as per the IR Playbook. Never conclude an investigation based on this tool alone.
- **API Limits:** Be mindful of your VirusTotal API quota (standard is 4 requests/min).
