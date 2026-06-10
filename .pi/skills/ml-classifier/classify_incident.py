import argparse
import json
import os

import joblib
import pandas as pd


FEATURE_COLUMNS = [
    "suspicious_command_count",
    "executable_evidence_count",
    "network_connection_count",
    "hash_evidence_count",
    "http_count",
    "dns_count",
    "smb_count",
    "unique_dest_ip_count",
    "external_connection_count",
    "bytes_out",
    "bytes_in",
    "has_webroot_executable",
    "has_cmd_execution",
    "has_powershell",
    "has_encoded_command",
]


def load_json(path):
    if not path or not os.path.exists(path):
        return {}

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def contains_text(data, keywords):
    text = json.dumps(data, ensure_ascii=False).lower()
    return any(keyword.lower() in text for keyword in keywords)


def extract_features_from_log(log_data):
    suspicious_commands = log_data.get("suspicious_commands", [])
    executable_evidence = log_data.get("executable_evidence", [])
    network_connections = log_data.get("network_connections", [])
    hash_evidence = log_data.get("hash_evidence", [])

    feature_vector = {
        "suspicious_command_count": len(suspicious_commands),
        "executable_evidence_count": len(executable_evidence),
        "network_connection_count": len(network_connections),
        "hash_evidence_count": len(hash_evidence),

        "http_count": 0,
        "dns_count": 0,
        "smb_count": 0,
        "unique_dest_ip_count": 0,
        "external_connection_count": 0,
        "bytes_out": 0,
        "bytes_in": 0,

        "has_webroot_executable": 1 if contains_text(
            log_data,
            ["\\inetpub\\", "\\wwwroot\\", "\\joomla\\", "\\uploads\\", "3791.exe"]
        ) else 0,

        "has_cmd_execution": 1 if contains_text(
            log_data,
            ["cmd.exe", "command_line"]
        ) else 0,

        "has_powershell": 1 if contains_text(
            log_data,
            ["powershell", "powershell.exe"]
        ) else 0,

        "has_encoded_command": 1 if contains_text(
            log_data,
            ["encodedcommand", "-enc"]
        ) else 0,
    }

    destination_ips = set()

    for conn in network_connections:
        dst = (
            conn.get("destination_ip")
            or conn.get("DestinationIp")
            or conn.get("dest_ip")
            or ""
        )

        port = str(
            conn.get("destination_port")
            or conn.get("DestinationPort")
            or conn.get("dest_port")
            or ""
        )

        if dst:
            destination_ips.add(dst)

        if port in ["80", "443", "8080"]:
            feature_vector["http_count"] += 1

        if port == "53":
            feature_vector["dns_count"] += 1

        if port in ["139", "445"]:
            feature_vector["smb_count"] += 1

    feature_vector["unique_dest_ip_count"] = len(destination_ips)

    return feature_vector


def merge_network_features(feature_vector, network_data):
    if not network_data:
        return feature_vector

    if "feature_vector" in network_data and isinstance(network_data["feature_vector"], dict):
        network_data = {**network_data, **network_data["feature_vector"]}

    # Current Network Analyzer schema support
    if isinstance(network_data.get("flow_count"), (int, float)):
        feature_vector["network_connection_count"] = max(
            feature_vector.get("network_connection_count", 0),
            int(network_data.get("flow_count", 0))
        )

    if isinstance(network_data.get("distinct_dest_count"), (int, float)):
        feature_vector["unique_dest_ip_count"] = int(network_data.get("distinct_dest_count", 0))

    if isinstance(network_data.get("total_volume_mb"), (int, float)):
        total_bytes = int(float(network_data.get("total_volume_mb", 0)) * 1024 * 1024)
        feature_vector["bytes_out"] = max(feature_vector.get("bytes_out", 0), total_bytes)

    top_protocol = str(network_data.get("top_protocol", "")).lower()

    if top_protocol in ["dns", "domain"]:
        feature_vector["dns_count"] = max(
            feature_vector.get("dns_count", 0),
            int(network_data.get("flow_count", 0))
        )

    if top_protocol in ["http", "https", "web"]:
        feature_vector["http_count"] = max(
            feature_vector.get("http_count", 0),
            int(network_data.get("flow_count", 0))
        )

    if top_protocol in ["smb", "cifs", "netbios"]:
        feature_vector["smb_count"] = max(
            feature_vector.get("smb_count", 0),
            int(network_data.get("flow_count", 0))
        )

    # Flexible schema support
    possible_mapping = {
        "http_count": ["http_count", "http_requests", "total_http"],
        "dns_count": ["dns_count", "dns_queries", "total_dns"],
        "smb_count": ["smb_count", "smb_sessions", "total_smb"],
        "unique_dest_ip_count": ["unique_dest_ip_count", "unique_dest_ips", "unique_dst_ips"],
        "external_connection_count": ["external_connection_count", "external_connections"],
        "bytes_out": ["bytes_out", "total_bytes_out", "outbound_bytes"],
        "bytes_in": ["bytes_in", "total_bytes_in", "inbound_bytes"],
    }

    for target_key, candidate_keys in possible_mapping.items():
        for candidate_key in candidate_keys:
            value = network_data.get(candidate_key)
            if isinstance(value, (int, float)):
                feature_vector[target_key] = value
                break

    return feature_vector


def predict_incident_type(feature_vector, model_file):
    if not os.path.exists(model_file):
        raise FileNotFoundError(f"Model file not found: {model_file}")

    bundle = joblib.load(model_file)

    model = bundle["model"]
    feature_columns = bundle["feature_columns"]
    model_type = bundle.get("model_type", "RandomForestClassifier")

    row = pd.DataFrame(
        [[feature_vector.get(col, 0) for col in feature_columns]],
        columns=feature_columns,
    )

    predicted_label = str(model.predict(row)[0])

    confidence = None
    probabilities = {}

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(row)[0]
        classes = model.classes_

        probabilities = {
            str(label): round(float(prob), 6)
            for label, prob in zip(classes, proba)
        }

        confidence = round(float(max(proba)), 6)

    return predicted_label, confidence, probabilities, model_type


def estimate_severity(predicted_incident_type, classification_confidence, feature_vector):
    high_types = [
        "Web Shell Malware Execution",
        "Malware Execution",
        "Data Exfiltration",
        "C2 Communication",
    ]

    medium_types = [
        "Brute Force",
        "Reconnaissance",
        "DNS Anomaly",
        "Suspicious Internal Activity",
        "Network Anomaly",
    ]

    if predicted_incident_type in high_types:
        return "high"

    if feature_vector.get("bytes_out", 0) >= 200 * 1024 * 1024:
        return "high"

    if feature_vector.get("suspicious_command_count", 0) >= 20:
        return "high"

    if predicted_incident_type in medium_types:
        return "medium"

    if feature_vector.get("network_connection_count", 0) >= 100:
        return "medium"

    return "low"


def build_evidence_used(log_data):
    evidence = []

    executable_evidence = log_data.get("executable_evidence", [])
    suspicious_commands = log_data.get("suspicious_commands", [])
    network_connections = log_data.get("network_connections", [])

    if executable_evidence:
        first = executable_evidence[0]
        evidence.append(
            "Executable evidence: "
            + str(first.get("image", ""))
            + " "
            + str(first.get("command_line", ""))
        )

    if suspicious_commands:
        first = suspicious_commands[0]
        evidence.append(
            "Suspicious command: "
            + str(first.get("command_line", ""))
        )

    if network_connections:
        evidence.append(
            f"Victim-related network connections from Log Collector: {len(network_connections)}"
        )

    return evidence


def map_mitre(predicted_incident_type, feature_vector, log_data):
    mappings = []
    text = json.dumps(log_data, ensure_ascii=False).lower()

    def add(technique_id, technique_name, tactic, evidence, confidence, source):
        mappings.append({
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "evidence": evidence,
            "confidence": confidence,
            "source": source,
        })

    suspicious_command_count = feature_vector.get("suspicious_command_count", 0)
    executable_evidence_count = feature_vector.get("executable_evidence_count", 0)
    network_connection_count = feature_vector.get("network_connection_count", 0)
    hash_evidence_count = feature_vector.get("hash_evidence_count", 0)

    http_count = feature_vector.get("http_count", 0)
    dns_count = feature_vector.get("dns_count", 0)
    smb_count = feature_vector.get("smb_count", 0)
    unique_dest_ip_count = feature_vector.get("unique_dest_ip_count", 0)
    bytes_out = feature_vector.get("bytes_out", 0)

    has_webroot_executable = feature_vector.get("has_webroot_executable", 0)
    has_cmd_execution = feature_vector.get("has_cmd_execution", 0)
    has_powershell = feature_vector.get("has_powershell", 0)
    has_encoded_command = feature_vector.get("has_encoded_command", 0)

    # Initial Access
    if has_webroot_executable == 1 or "\\inetpub\\" in text or "\\wwwroot\\" in text or "\\joomla\\" in text:
        add(
            "T1190",
            "Exploit Public-Facing Application",
            "Initial Access",
            "Suspicious activity is associated with a public web application or webroot directory.",
            "medium",
            "log_collector",
        )

    # Execution
    if has_cmd_execution == 1 or "cmd.exe" in text:
        add(
            "T1059",
            "Command and Scripting Interpreter",
            "Execution",
            "Command execution evidence was observed, including cmd.exe or command-line process activity.",
            "high",
            "log_collector",
        )

    if has_powershell == 1 or "powershell" in text:
        add(
            "T1059.001",
            "PowerShell",
            "Execution",
            "PowerShell execution was observed in process or command-line evidence.",
            "high",
            "log_collector",
        )

    if executable_evidence_count >= 1 and hash_evidence_count >= 1:
        add(
            "T1204.002",
            "Malicious File",
            "Execution",
            "Executable and hash evidence were observed, suggesting malicious file execution.",
            "medium",
            "log_collector",
        )

    # Persistence
    if has_webroot_executable == 1 or "3791.exe" in text or "\\wwwroot\\" in text or "\\joomla\\" in text:
        add(
            "T1505.003",
            "Web Shell",
            "Persistence",
            "Executable or command execution evidence was found under a webroot/Joomla path.",
            "high",
            "log_collector",
        )

    # Defense Evasion
    if has_encoded_command == 1 or "encodedcommand" in text or " -enc" in text:
        add(
            "T1027",
            "Obfuscated Files or Information",
            "Defense Evasion",
            "Encoded or obfuscated command execution was observed.",
            "medium",
            "log_collector",
        )

    if any(tool in text for tool in ["wscript", "cscript", "regsvr32", "rundll32"]):
        add(
            "T1218",
            "System Binary Proxy Execution",
            "Defense Evasion",
            "Windows signed binaries such as rundll32/regsvr32/script interpreters were observed.",
            "medium",
            "log_collector",
        )

    # Discovery
    if any(cmd in text for cmd in ["whoami", "tasklist", "ipconfig", "net.exe", "net user", "net group"]):
        add(
            "T1087",
            "Account Discovery",
            "Discovery",
            "Account or system discovery commands were observed.",
            "medium",
            "log_collector",
        )

    if unique_dest_ip_count >= 20:
        add(
            "T1046",
            "Network Service Discovery",
            "Discovery",
            "High number of unique destination IPs may indicate network service discovery.",
            "medium",
            "network_analyzer",
        )

    # Lateral Movement
    if smb_count >= 5:
        add(
            "T1021",
            "Remote Services",
            "Lateral Movement",
            "SMB or remote-service-like traffic was observed in the network feature vector.",
            "medium",
            "network_analyzer",
        )

    if smb_count >= 20:
        add(
            "T1021.002",
            "SMB/Windows Admin Shares",
            "Lateral Movement",
            "High SMB activity may indicate Windows admin shares or lateral movement.",
            "medium",
            "network_analyzer",
        )

    # Command and Control
    if (
        predicted_incident_type in [
            "Network Anomaly",
            "DNS Anomaly",
            "Web Shell Malware Execution",
            "Malware Execution",
            "C2 Communication",
        ]
        and network_connection_count >= 100
    ):
        add(
            "T1071",
            "Application Layer Protocol",
            "Command and Control",
            "High network flow count was observed, suggesting possible application-layer C2 or abnormal communication.",
            "medium",
            "network_analyzer",
        )

    if dns_count > 0:
        add(
            "T1071.004",
            "DNS",
            "Command and Control",
            "DNS-related network activity was observed in the incident feature vector.",
            "medium",
            "network_analyzer",
        )

    if http_count > 0:
        add(
            "T1071.001",
            "Web Protocols",
            "Command and Control",
            "HTTP/HTTPS-related activity was observed in the incident feature vector.",
            "low",
            "network_analyzer",
        )

    # Exfiltration
    if bytes_out >= 50 * 1024 * 1024:
        add(
            "T1041",
            "Exfiltration Over C2 Channel",
            "Exfiltration",
            "Large outbound data volume was observed by Network Analyzer.",
            "medium",
            "network_analyzer",
        )

    if bytes_out >= 200 * 1024 * 1024:
        add(
            "T1041",
            "Exfiltration Over C2 Channel",
            "Exfiltration",
            "Very large outbound data volume was observed, increasing suspicion of data exfiltration.",
            "high",
            "network_analyzer",
        )

    # Credential Access
    if predicted_incident_type == "Brute Force":
        add(
            "T1110",
            "Brute Force",
            "Credential Access",
            "The ML classifier predicted brute-force incident behavior.",
            "medium",
            "ml_classifier",
        )

    # Impact
    if "vssadmin" in text:
        add(
            "T1490",
            "Inhibit System Recovery",
            "Impact",
            "vssadmin usage was observed, which may indicate recovery inhibition.",
            "medium",
            "log_collector",
        )

    # Deduplicate by technique_id, keep highest confidence
    confidence_rank = {
        "low": 1,
        "medium": 2,
        "high": 3,
    }

    deduped = {}

    for item in mappings:
        tid = item["technique_id"]

        if tid not in deduped:
            deduped[tid] = item
            continue

        old_conf = confidence_rank.get(str(deduped[tid]["confidence"]).lower(), 0)
        new_conf = confidence_rank.get(str(item["confidence"]).lower(), 0)

        if new_conf > old_conf:
            deduped[tid] = item

    tactic_order = {
        "Initial Access": 1,
        "Execution": 2,
        "Persistence": 3,
        "Privilege Escalation": 4,
        "Defense Evasion": 5,
        "Credential Access": 6,
        "Discovery": 7,
        "Lateral Movement": 8,
        "Command and Control": 9,
        "Exfiltration": 10,
        "Impact": 11,
    }

    unique = list(deduped.values())

    unique.sort(
        key=lambda x: (
            tactic_order.get(x.get("tactic", ""), 99),
            x.get("technique_id", "")
        )
    )

    return unique


def classify_incident(log_file, network_file, model_file, output_file):
    log_data = load_json(log_file)
    network_data = load_json(network_file) if network_file else {}

    if not log_data:
        raise FileNotFoundError(f"Log file not found or empty: {log_file}")

    feature_vector = extract_features_from_log(log_data)
    feature_vector = merge_network_features(feature_vector, network_data)

    predicted_incident_type, confidence, probabilities, model_type = predict_incident_type(
        feature_vector,
        model_file,
    )

    severity = estimate_severity(
        predicted_incident_type,
        confidence,
        feature_vector,
    )

    mitre_mapping = map_mitre(
        predicted_incident_type,
        feature_vector,
        log_data,
    )

    evidence_used = build_evidence_used(log_data)

    result = {
        "agent": "ml_classifier",
        "model": model_type,
        "input_sources": {
            "log_file": log_file,
            "network_file": network_file if network_file and os.path.exists(network_file) else None,
            "model_file": model_file,
        },
        "predicted_incident_type": predicted_incident_type,
        "classification_confidence": confidence,
        "class_probabilities": probabilities,
        "severity": severity,
        "feature_vector": feature_vector,
        "evidence_used": evidence_used,
        "mitre_mapping": mitre_mapping,
        "summary": (
            f"RandomForest classified this alert as {predicted_incident_type} "
            f"with confidence={confidence}. The classification used a combined feature vector "
            f"from Log Collector and Network Analyzer outputs. "
            f"Log Collector contributed host/process evidence such as suspicious commands, "
            f"executable evidence, hashes, webroot execution, cmd.exe and PowerShell indicators. "
            f"Network Analyzer contributed network telemetry such as flow count, unique destinations, "
            f"and outbound bytes. Severity is {severity}. "
            f"{len(mitre_mapping)} MITRE ATT&CK technique(s) were mapped."
        ),
    }

    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print("ML incident classification completed.")
    print(f"Model: {model_type}")
    print(f"Predicted incident type: {predicted_incident_type}")
    print(f"Classification confidence: {confidence}")
    print(f"Severity: {severity}")
    print(f"MITRE mappings: {len(mitre_mapping)}")
    print(f"Output saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Classify incident type using RandomForest and MITRE mapping."
    )

    parser.add_argument(
        "--log-file",
        default="./reports/log_collector_result.json",
        help="Path to Log Collector JSON output.",
    )

    parser.add_argument(
        "--network-file",
        default="",
        help="Optional path to Network Analyzer JSON output.",
    )

    parser.add_argument(
        "--model-file",
        default="./.pi/models/random_forest_incident_classifier.pkl",
        help="Path to trained RandomForest model.",
    )

    parser.add_argument(
        "--output-file",
        default="./reports/ml_classification_result.json",
        help="Path to save ML classification result.",
    )

    args = parser.parse_args()

    classify_incident(
        log_file=args.log_file,
        network_file=args.network_file,
        model_file=args.model_file,
        output_file=args.output_file,
    )


if __name__ == "__main__":
    main()