import argparse
import html
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from collections import Counter


SUSPICIOUS_KEYWORDS = [
    "powershell",
    "powershell.exe",
    "cmd.exe",
    "certutil",
    "rundll32",
    "regsvr32",
    "wscript",
    "cscript",
    "schtasks",
    "wmic",
    "bitsadmin",
    "net.exe",
    "whoami",
    "tasklist",
    "vssadmin",
    "encodedcommand",
    "-enc",
    "downloadstring",
    "invoke-webrequest",
    "invoke-expression",
    "iex",
    "3791.exe",
]

WEBROOT_HINTS = [
    "\\inetpub\\",
    "\\wwwroot\\",
    "\\joomla\\",
    "\\uploads\\",
    "\\xampp\\",
    "\\htdocs\\",
]

EXECUTABLE_HINTS = [
    "\\users\\",
    "\\appdata\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\inetpub\\",
    "\\wwwroot\\",
    "\\joomla\\",
    "\\uploads\\",
    "\\xampp\\",
    "\\htdocs\\",
]

KNOWN_WINDOWS_PROCESSES = {
    "searchprotocolhost.exe",
    "searchfilterhost.exe",
    "wmiprvse.exe",
    "svchost.exe",
    "lsass.exe",
    "dns.exe",
    "explorer.exe",
    "services.exe",
}


def parse_time(value):
    """Parse Splunk/Sysmon timestamps and normalize to UTC-aware datetime."""
    if not value:
        return None

    value = str(value).strip().replace("Z", "+0000")

    # Convert +0700 to +07:00 for datetime.fromisoformat
    if len(value) > 5 and value[-5] in ["+", "-"] and value[-3] != ":":
        value = value[:-2] + ":" + value[-2:]

    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo:
            return dt.astimezone(timezone.utc)
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    ]

    for fmt in formats:
        try:
            sliced_value = value[:26] if "." in value else value[:19]
            dt = datetime.strptime(sliced_value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return None


def get_filtered_lines(file_path, keywords):
    """
    Grep-first strategy:
    - Use grep for speed on large BOTSv1 Sysmon NDJSON files.
    - Fall back to Python line scanning if grep is unavailable.
    """
    try:
        pattern = "|".join(re.escape(k) for k in keywords if k)
        cmd = ["grep", "-i", "-E", pattern, file_path]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )

        for line in proc.stdout:
            yield line

        proc.wait()
        if proc.returncode == 0:
            return
    except Exception:
        pass

    if os.path.exists(file_path):
        lowered_keywords = [k.lower() for k in keywords if k]
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                lowered_line = line.lower()
                if any(k in lowered_line for k in lowered_keywords):
                    yield line


def parse_hashes(hashes):
    """Convert Sysmon Hashes field to a dictionary."""
    result = {}

    if not hashes:
        return result

    for item in str(hashes).split(","):
        if "=" not in item:
            continue

        key, value = item.split("=", 1)
        key = key.strip().upper()
        value = value.strip()

        if key and value:
            result[key] = value

    return result


def extract_xml_fields(raw, data):
    """Extract EventID and selected EventData fields from Sysmon XML stored in _raw."""
    if not raw or not isinstance(raw, str):
        return data

    raw = html.unescape(raw)

    event_id_match = re.search(r"<EventID[^>]*>(.*?)</EventID>", raw, re.IGNORECASE | re.DOTALL)
    if event_id_match:
        data["EventID"] = event_id_match.group(1).strip()

    fields = [
        "UtcTime",
        "Image",
        "CommandLine",
        "CurrentDirectory",
        "User",
        "ParentImage",
        "ParentCommandLine",
        "SourceIp",
        "SourcePort",
        "DestinationIp",
        "DestinationPort",
        "Protocol",
        "Hashes",
    ]

    for field in fields:
        pattern = rf"<Data\s+Name=['\"]{re.escape(field)}['\"]>(.*?)</Data>"
        match = re.search(pattern, raw, re.IGNORECASE | re.DOTALL)
        if match:
            data[field] = html.unescape(match.group(1).strip())

    return data


def basename_windows(path):
    if not path:
        return ""

    normalized = str(path).replace("/", "\\")
    return normalized.split("\\")[-1].lower()


def is_interesting_executable(image, command_line="", parent_image="", current_directory=""):
    """
    Mark executable evidence if a .exe appears in a user/web/upload path,
    but avoid common Windows processes to reduce false positives.
    """
    combined = " ".join(
        str(x) for x in [image, command_line, parent_image, current_directory] if x
    ).lower()

    image_name = basename_windows(image)
    parent_name = basename_windows(parent_image)

    if image_name in KNOWN_WINDOWS_PROCESSES and parent_name in KNOWN_WINDOWS_PROCESSES:
        return False

    has_exe = ".exe" in combined
    has_suspicious_path = any(hint in combined for hint in EXECUTABLE_HINTS)
    has_webroot_path = any(hint in combined for hint in WEBROOT_HINTS)
    has_known_ioc = "3791.exe" in combined

    return has_exe and (has_suspicious_path or has_webroot_path or has_known_ioc)


def build_process_event(data, ts_str):
    return {
        "time": ts_str,
        "image": data.get("Image", ""),
        "command_line": data.get("CommandLine", ""),
        "current_directory": data.get("CurrentDirectory", ""),
        "user": data.get("User", ""),
        "parent_image": data.get("ParentImage", ""),
        "parent_command_line": data.get("ParentCommandLine", ""),
    }


def collect_logs(dest_ip, target_timestamp, window_minutes=5, input_file="./data/sysmon_logs_botsv1.json"):
    if not os.path.exists(input_file):
        return {
            "agent": "log_collector",
            "error": f"File {input_file} not found",
        }

    target_time = parse_time(target_timestamp)
    if not target_time:
        return {
            "agent": "log_collector",
            "error": "Invalid target timestamp",
            "target_timestamp": target_timestamp,
        }

    start_window = target_time - timedelta(minutes=window_minutes)
    end_window = target_time + timedelta(minutes=window_minutes)

    result = {
        "agent": "log_collector",
        "victim_ip": dest_ip,
        "target_timestamp": target_timestamp,
        "window_minutes": window_minutes,
        "time_window": {
            "start": start_window.isoformat(),
            "end": end_window.isoformat(),
        },
        "event_id_counter": Counter(),
        "total_events_in_window": 0,
        "suspicious_processes": [],
        "suspicious_commands": [],
        "network_connections": [],
        "executable_evidence": [],
        "hash_evidence": [],
    }

    # Grep for victim IP and host-based suspicious indicators.
    grep_keywords = [dest_ip] + SUSPICIOUS_KEYWORDS + WEBROOT_HINTS

    for line in get_filtered_lines(input_file, grep_keywords):
        try:
            record = json.loads(line)
            data = record.get("result", record)

            raw = data.get("_raw")

            if raw and isinstance(raw, str):
                if raw.strip().startswith("{"):
                    try:
                        data.update(json.loads(raw))
                    except json.JSONDecodeError:
                        pass
                elif "<Event" in raw:
                    data = extract_xml_fields(raw, data)

            ts_str = data.get("UtcTime") or data.get("timestamp") or data.get("_time")
            curr_time = parse_time(ts_str)

            if not curr_time or not (start_window <= curr_time <= end_window):
                continue

            eid = str(data.get("EventID") or data.get("EventCode") or "").strip()
            result["event_id_counter"][eid] += 1
            result["total_events_in_window"] += 1

            if eid == "1":
                process_event = build_process_event(data, ts_str)

                combined_text = json.dumps(process_event, ensure_ascii=False).lower()

                if any(kw.lower() in combined_text for kw in SUSPICIOUS_KEYWORDS):
                    result["suspicious_processes"].append(process_event)
                    result["suspicious_commands"].append(process_event)

                if is_interesting_executable(
                    image=data.get("Image", ""),
                    command_line=data.get("CommandLine", ""),
                    parent_image=data.get("ParentImage", ""),
                    current_directory=data.get("CurrentDirectory", ""),
                ):
                    result["executable_evidence"].append(process_event)

                hashes = parse_hashes(data.get("Hashes", ""))
                if hashes:
                    result["hash_evidence"].append(
                        {
                            "time": ts_str,
                            "image": data.get("Image", ""),
                            "command_line": data.get("CommandLine", ""),
                            "parent_image": data.get("ParentImage", ""),
                            "hashes": hashes,
                        }
                    )

            elif eid == "3":
                source_ip = data.get("SourceIp", "")
                destination_ip = data.get("DestinationIp", "")

                if source_ip == dest_ip or destination_ip == dest_ip:
                    result["network_connections"].append(
                        {
                            "time": ts_str,
                            "image": data.get("Image", ""),
                            "source_ip": source_ip,
                            "source_port": data.get("SourcePort", ""),
                            "destination_ip": destination_ip,
                            "destination_port": data.get("DestinationPort", ""),
                            "protocol": data.get("Protocol", ""),
                        }
                    )

        except Exception:
            # Skip malformed lines, but keep the collector resilient for large noisy logs.
            continue

    result["event_id_counter"] = dict(result["event_id_counter"])

    suspicious_count = len(result["suspicious_commands"])
    executable_count = len(result["executable_evidence"])
    network_count = len(result["network_connections"])
    hash_count = len(result["hash_evidence"])

    if executable_count >= 1 or suspicious_count >= 3:
        risk_level = "high"
    elif suspicious_count >= 1 or network_count >= 10 or hash_count >= 1:
        risk_level = "medium"
    else:
        risk_level = "low"

    result["risk_level"] = risk_level
    result["summary"] = (
        f"Found {suspicious_count} suspicious command event(s), "
        f"{executable_count} executable evidence record(s), "
        f"{network_count} victim-related network connection(s), "
        f"and {hash_count} hash evidence record(s). "
        f"Risk level: {risk_level}."
    )
    result["analysis_summary"] = result["summary"]

    return result


def main():
    parser = argparse.ArgumentParser(description="Collect Sysmon log evidence for incident response.")
    parser.add_argument("--dest-ip", required=True, help="Victim IP address.")
    parser.add_argument("--target-timestamp", required=True, help="Alert timestamp.")
    parser.add_argument("--window", type=int, default=5, help="Time window in minutes.")
    parser.add_argument("--input-file", default="./data/sysmon_logs_botsv1.json", help="Path to Sysmon NDJSON file.")
    parser.add_argument("--output-file", default="./reports/log_collector_result.json", help="Output JSON path.")

    args = parser.parse_args()

    res = collect_logs(
        dest_ip=args.dest_ip,
        target_timestamp=args.target_timestamp,
        window_minutes=args.window,
        input_file=args.input_file,
    )

    output_dir = os.path.dirname(os.path.abspath(args.output_file))
    os.makedirs(output_dir, exist_ok=True)

    with open(args.output_file, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)

    print("Log collection complete.")
    print(f"Results saved to {args.output_file}")

    if "error" in res:
        print(f"Error: {res['error']}")
    else:
        print(res.get("summary", ""))


if __name__ == "__main__":
    main()
