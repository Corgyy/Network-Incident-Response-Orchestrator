import argparse
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from collections import Counter


SUSPICIOUS_KEYWORDS = [
    "powershell",
    "powershell.exe",
    "cmd.exe",
    "rundll32",
    "rundll32.exe",
    "regsvr32",
    "regsvr32.exe",
    "wscript",
    "wscript.exe",
    "cscript",
    "cscript.exe",
    "certutil",
    "certutil.exe",
    "encodedcommand",
    "-enc",
    "downloadstring",
    "invoke-webrequest",
    "invoke-expression",
    "iex",
    "net user",
    "whoami",
    "ipconfig",
    "tasklist",
    "schtasks",
    "wmic",
    "psexec",
    "mimikatz"
]

EXECUTABLE_HINTS = [
    "\\users\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\inetpub\\",
    "\\wwwroot\\",
    "\\xampp\\",
    "\\htdocs\\",
    "\\uploads\\"
]

KNOWN_WINDOWS_PROCESSES = [
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "wmiprvse.exe",
    "svchost.exe",
    "lsass.exe",
    "dns.exe",
    "explorer.exe",
    "services.exe"
]


def parse_time(value):
    if not value:
        return None

    value = str(value).strip()
    value = value.replace("Z", "+0000")

    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%m/%d/%Y %H:%M:%S"
    ]

    for fmt in formats:
        try:
            parsed = datetime.strptime(value[:32], fmt)

            if parsed.tzinfo is not None:
                parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)

            return parsed
        except ValueError:
            continue

    return None


def iter_json_records(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
        content = file.read().strip()

    if not content:
        return

    try:
        data = json.loads(content)

        if isinstance(data, list):
            for item in data:
                yield item
            return

        if isinstance(data, dict):
            if isinstance(data.get("results"), list):
                for item in data["results"]:
                    yield item
                return

            yield data
            return

    except json.JSONDecodeError:
        pass

    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def unwrap_splunk_record(record):
    if isinstance(record, dict) and isinstance(record.get("result"), dict):
        return record["result"]

    return record


def parse_sysmon_xml(raw_xml):
    parsed = {}

    if not raw_xml or "<Event" not in str(raw_xml):
        return parsed

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return parsed

    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    event_id = root.findtext(".//e:System/e:EventID", namespaces=namespace)
    computer = root.findtext(".//e:System/e:Computer", namespaces=namespace)

    time_created = ""
    time_node = root.find(".//e:System/e:TimeCreated", namespaces=namespace)

    if time_node is not None:
        time_created = time_node.attrib.get("SystemTime", "")

    parsed["EventID"] = event_id or ""
    parsed["Computer"] = computer or ""
    parsed["TimeCreated"] = time_created or ""

    for data_node in root.findall(".//e:EventData/e:Data", namespaces=namespace):
        name = data_node.attrib.get("Name")
        value = data_node.text or ""

        if name:
            parsed[name] = value

    return parsed


def normalize_event(record):
    record = unwrap_splunk_record(record)
    normalized = dict(record)

    xml_fields = parse_sysmon_xml(record.get("_raw", ""))
    normalized.update(xml_fields)

    return normalized


def get_field(event, names):
    for name in names:
        value = event.get(name)

        if value not in [None, ""]:
            return value

    return ""


def is_suspicious_text(text):
    if not text:
        return False

    lowered = str(text).lower()
    return any(keyword in lowered for keyword in SUSPICIOUS_KEYWORDS)


def is_interesting_executable(image, command_line):
    combined = f"{image} {command_line}".lower()
    image_name = os.path.basename(str(image)).lower()

    if image_name in KNOWN_WINDOWS_PROCESSES:
        return False

    if ".exe" not in combined:
        return False

    return any(hint in combined for hint in EXECUTABLE_HINTS)


def extract_hash_map(hash_text):
    result = {}

    if not hash_text:
        return result

    parts = re.split(r"[,\s]+", str(hash_text))

    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            key = key.strip().upper()
            value = value.strip()

            if key and value:
                result[key] = value

    return result


def extract_alert_context(alert_file):
    for raw_record in iter_json_records(alert_file):
        record = unwrap_splunk_record(raw_record)

        src_ip = get_field(record, ["src_ip", "SourceIp", "source_ip"])
        dest_ip = get_field(record, ["dest_ip", "DestinationIp", "destination_ip"])
        timestamp = get_field(record, ["_time", "timestamp", "TimeCreated", "UtcTime"])

        raw = record.get("_raw", "")

        if raw and str(raw).strip().startswith("{"):
            try:
                raw_obj = json.loads(raw)
                src_ip = src_ip or raw_obj.get("src_ip", "")
                dest_ip = dest_ip or raw_obj.get("dest_ip", "")
                timestamp = timestamp or raw_obj.get("timestamp", "")
            except json.JSONDecodeError:
                pass

        return {
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "timestamp": timestamp
        }

    return {
        "src_ip": "",
        "dest_ip": "",
        "timestamp": ""
    }


def analyze_sysmon_logs(input_file, dest_ip, target_timestamp, window_minutes):
    alert_time = parse_time(target_timestamp)

    if alert_time is None:
        raise ValueError(f"Invalid target timestamp: {target_timestamp}")

    start_time = alert_time - timedelta(minutes=window_minutes)
    end_time = alert_time + timedelta(minutes=window_minutes)

    total_logs_loaded = 0
    total_events_in_window = 0

    event_id_counter = Counter()
    suspicious_processes = []
    suspicious_commands = []
    network_connections = []
    executable_evidence = []
    hash_evidence = []

    for raw_record in iter_json_records(input_file):
        total_logs_loaded += 1

        event = normalize_event(raw_record)

        event_id = str(get_field(event, ["EventID", "EventCode", "event_id"]))
        event_id_counter[event_id] += 1

        event_time_raw = get_field(event, ["UtcTime", "TimeCreated", "_time", "timestamp"])
        event_time = parse_time(event_time_raw)

        if event_time is None:
            continue

        if not (start_time <= event_time <= end_time):
            continue

        total_events_in_window += 1

        if event_id == "1":
            image = get_field(event, ["Image", "process_name", "NewProcessName"])
            parent_image = get_field(event, ["ParentImage", "parent_process_name"])
            command_line = get_field(event, ["CommandLine", "ProcessCommandLine", "cmdline"])
            user = get_field(event, ["User", "user"])
            computer = get_field(event, ["Computer", "host", "dest"])
            current_directory = get_field(event, ["CurrentDirectory", "current_directory"])
            hashes = get_field(event, ["Hashes", "hashes", "MD5", "md5"])

            process_info = {
                "time": event_time_raw,
                "computer": computer,
                "image": image,
                "parent_image": parent_image,
                "command_line": command_line,
                "current_directory": current_directory,
                "user": user,
                "hashes": hashes
            }

            if is_suspicious_text(command_line) or is_suspicious_text(image):
                suspicious_processes.append(process_info)
                suspicious_commands.append({
                    "time": event_time_raw,
                    "computer": computer,
                    "image": image,
                    "command_line": command_line,
                    "reason": "Suspicious command or LOLBin detected"
                })

            if is_interesting_executable(image, command_line):
                executable_evidence.append(process_info)

            parsed_hashes = extract_hash_map(hashes)

            if parsed_hashes:
                hash_evidence.append({
                    "time": event_time_raw,
                    "computer": computer,
                    "image": image,
                    "command_line": command_line,
                    "hashes": parsed_hashes
                })

        elif event_id == "3":
            image = get_field(event, ["Image", "process_name"])
            src_ip = get_field(event, ["SourceIp", "src_ip"])
            src_port = get_field(event, ["SourcePort", "src_port"])
            dst_ip = get_field(event, ["DestinationIp", "dest_ip"])
            dst_port = get_field(event, ["DestinationPort", "dest_port"])
            protocol = get_field(event, ["Protocol", "protocol"])
            computer = get_field(event, ["Computer", "host", "dest"])

            if dest_ip:
                if src_ip != dest_ip and dst_ip != dest_ip:
                    continue

            network_connections.append({
                "time": event_time_raw,
                "computer": computer,
                "process": image,
                "src_ip": src_ip,
                "src_port": src_port,
                "dest_ip": dst_ip,
                "dest_port": dst_port,
                "protocol": protocol
            })

    risk_level = "low"

    if len(suspicious_commands) >= 3 or len(executable_evidence) >= 1:
        risk_level = "high"
    elif len(suspicious_commands) >= 1 or len(network_connections) >= 10:
        risk_level = "medium"

    result = {
        "agent": "log_collector",
        "victim_ip": dest_ip,
        "target_timestamp": target_timestamp,
        "time_window": {
            "start": start_time.isoformat(),
            "end": end_time.isoformat()
        },
        "total_logs_loaded": total_logs_loaded,
        "total_events_in_window": total_events_in_window,
        "event_id_counter": dict(event_id_counter),
        "suspicious_processes": suspicious_processes,
        "suspicious_commands": suspicious_commands,
        "network_connections": network_connections,
        "executable_evidence": executable_evidence,
        "hash_evidence": hash_evidence,
        "summary": (
            f"Found {len(suspicious_processes)} suspicious process events, "
            f"{len(suspicious_commands)} suspicious command lines, "
            f"{len(network_connections)} victim-related network connections, "
            f"{len(executable_evidence)} executable evidence records, and "
            f"{len(hash_evidence)} hash evidence records."
        ),
        "risk_level": risk_level
    }

    return result


def save_output(result, output_file):
    output_dir = os.path.dirname(output_file)

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(description="BOTSv1 Sysmon Log Collector Agent")

    parser.add_argument("--input-file", required=True, help="Path to sysmon_logs_botsv1.json")
    parser.add_argument("--alert-file", help="Optional path to alerts_trigger_botsv1.json")
    parser.add_argument("--dest-ip", help="Victim destination IP")
    parser.add_argument("--target-timestamp", help="Alert timestamp")
    parser.add_argument("--window", type=int, default=5, help="Time window in minutes")
    parser.add_argument("--output-file", default=".pi/output/log_collector_result.json", help="Output JSON path")

    args = parser.parse_args()

    alert_context = {}

    dest_ip = args.dest_ip
    target_timestamp = args.target_timestamp

    if args.alert_file:
        alert_context = extract_alert_context(args.alert_file)
        dest_ip = dest_ip or alert_context.get("dest_ip")
        target_timestamp = target_timestamp or alert_context.get("timestamp")

    if not dest_ip:
        raise ValueError("Missing dest_ip. Provide --dest-ip or --alert-file.")

    if not target_timestamp:
        raise ValueError("Missing target timestamp. Provide --target-timestamp or --alert-file.")

    result = analyze_sysmon_logs(
        input_file=args.input_file,
        dest_ip=dest_ip,
        target_timestamp=target_timestamp,
        window_minutes=args.window
    )

    result["alert_context"] = alert_context

    save_output(result, args.output_file)

    print("Log Collector analysis completed.")
    print(f"Victim IP: {dest_ip}")
    print(f"Target timestamp: {target_timestamp}")
    print(f"Window: ±{args.window} minutes")
    print(f"Risk level: {result['risk_level']}")
    print(f"Suspicious commands: {len(result['suspicious_commands'])}")
    print(f"Network connections: {len(result['network_connections'])}")
    print(f"Executable evidence: {len(result['executable_evidence'])}")
    print(f"Hash evidence: {len(result['hash_evidence'])}")
    print(f"Output saved to: {args.output_file}")


if __name__ == "__main__":
    main()