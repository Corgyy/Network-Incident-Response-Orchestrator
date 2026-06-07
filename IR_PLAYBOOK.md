# INCIDENT RESPONSE RULES OF ENGAGEMENT (IR PLAYBOOK)

This document mandates the standard operating procedure (SOP) for the Network Incident Response Orchestrator. Adherence to this pipeline is **mandatory** for every investigation request.

## 1. The Core Directive: Ground Truth over OSINT
**RULE #1:** Internal system and network logs (Sysmon/Network Streams) are the **Ground Truth**.
**RULE #2:** Global Intelligence (OSINT/VirusTotal) is for **Enrichment Only**.
**RULE #3:** A "Clean" or "Benign" report from VirusTotal (0 malicious engines) **DOES NOT** conclude an investigation. You are strictly forbidden from stopping after Bước 1 based on OSINT results.

## 2. Standard Operating Procedure (SOP)

### PHASE 0: Mandatory Triage
*   **Action:** Call `alert-triage-agent` immediately.
*   **Input:** Use the most specific IOC available (IP, Hash, or Signature).
*   **Output:** You MUST extract the `attacker_ip`, `victim_ip`, and the `recommended_window_minutes`.

### PHASE 1: Intelligence Enrichment
*   **Action:** Call `recon-analyzer` for the primary Attacker IP and any Domains found.
*   **Constraint:** Treat the result as a hint, never as a conclusion. Proceed to Phase 2 regardless of the score.

### PHASE 2: Deep Evidence Collection (Stage 1 Parallel)
*   **Action:** Execute `log-collector` and `network-protocol-analyzer` using the precise parameters provided by Step 0.
*   **Pivoting Rule:** If `log-collector` discovers new file hashes (e.g., `3791.exe`), you MUST re-trigger Phase 1 for those specific hashes.

### PHASE 3: Synthesis & Final Verdict (Stage 2)
*   **Action:** Correlate all findings (IDS Alerts + OSINT + Host Logs + Network Flows).
*   **Mapping:** Map all identified behaviors to the **MITRE ATT&CK Framework**.
*   **Containment:** Provide actionable containment steps.

## 3. Environment & Technical Standards
*   **Pathing:** Use only **relative paths** (e.g., `./.pi/data/...`) for maximum compatibility.
*   **Python:** Always invoke scripts using `python3`.
*   **Timeouts:** For large log files, use the `timeout` command or increase internal script timeouts.

---
*MANDate: Failure to complete all 4 phases will result in an incomplete investigation report.*
