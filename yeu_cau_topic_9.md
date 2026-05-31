## Topic 09 — Network Incident Response Orchestrator

### One-line description
A full incident response pipeline triggered by an alert: runs parallel recon and log collection, classifies the incident with ML, maps it to MITRE ATT&CK, and produces a structured IR report with containment steps.

### Parallelism benefit
Recon, log collection, and PCAP feature extraction are fully independent data-gathering tasks. Running Stage 1 in parallel compresses three sequential investigation steps into one. Stage 2 further parallelizes ML and embedding scoring on independent data streams.