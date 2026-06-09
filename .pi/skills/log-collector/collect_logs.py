import argparse
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from collections import Counter

SUSPICIOUS_KEYWORDS = [
    "powershell", "cmd.exe", "certutil", "rundll32", "regsvr32", "wscript", 
    "schtasks", "wmic", "bitsadmin", "net.exe", "whoami", "tasklist", "vssadmin", "3791.exe"
]

def parse_time(value):
    if not value: return None
    value = str(value).strip().replace("Z", "+0000")
    for fmt in ["%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]:
        try:
            return datetime.strptime(value[:26] if '.' in value else value[:19], fmt.split('%z')[0]).replace(tzinfo=timezone.utc)
        except ValueError: continue
    return None

def get_filtered_lines(file_path, keywords):
    try:
        pattern = "|".join([re.escape(k) for k in keywords])
        cmd = ["grep", "-i", "-E", pattern, file_path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='ignore')
        for line in proc.stdout: yield line
        proc.wait()
        if proc.returncode == 0: return
    except Exception: pass

    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if any(k.lower() in line.lower() for k in keywords): yield line

def collect_logs(dest_ip, target_timestamp, window_minutes=5, input_file="./data/sysmon_logs_botsv1.json"):
    if not os.path.exists(input_file): return {"error": f"File {input_file} not found"}

    target_time = parse_time(target_timestamp)
    if not target_time: return {"error": "Invalid target timestamp"}
    start_window = target_time - timedelta(minutes=window_minutes)
    end_window = target_time + timedelta(minutes=window_minutes)

    result = {
        "victim_ip": dest_ip,
        "time_window": f"{start_window} to {end_window}",
        "event_id_counter": Counter(),
        "suspicious_processes": [],
        "suspicious_commands": [],
        "network_connections": [],
        "executable_evidence": [],
        "hash_evidence": []
    }

    for line in get_filtered_lines(input_file, [dest_ip] + SUSPICIOUS_KEYWORDS):
        try:
            record = json.loads(line)
            data = record.get('result', record)
            raw = data.get('_raw')
            if raw and isinstance(raw, str) and raw.strip().startswith('{'):
                try: data.update(json.loads(raw))
                except json.JSONDecodeError: pass

            ts_str = data.get('UtcTime') or data.get('timestamp') or data.get('_time')
            if not ts_str: continue
            curr_time = parse_time(ts_str)
            if not curr_time or not (start_window <= curr_time <= end_window): continue

            eid = str(data.get('EventID') or data.get('EventCode', ''))
            result["event_id_counter"][eid] += 1

            if eid == '1':
                cmd_line = data.get('CommandLine', '').lower()
                image = data.get('Image', '')
                if any(kw in cmd_line for kw in SUSPICIOUS_KEYWORDS):
                    ev = {"time": ts_str, "image": image, "command_line": data.get('CommandLine'), "user": data.get('User')}
                    result["suspicious_processes"].append(ev)
                    result["suspicious_commands"].append(ev)
                    hashes = data.get('Hashes', '')
                    if hashes:
                        h_dict = {h.split('=')[0]: h.split('=')[1] for h in hashes.split(',') if '=' in h}
                        result["hash_evidence"].append({"image": image, "hashes": h_dict})
            elif eid == '3':
                if data.get('SourceIp') == dest_ip or data.get('DestinationIp') == dest_ip:
                    result["network_connections"].append({"time": ts_str, "image": data.get('Image'), "destination_ip": data.get('DestinationIp'), "destination_port": data.get('DestinationPort')})
        except Exception: continue

    result["event_id_counter"] = dict(result["event_id_counter"])
    result["risk_level"] = "high" if result["suspicious_commands"] else "low"
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect Log Evidence (Grep-First)")
    parser.add_argument("--dest-ip", required=True)
    parser.add_argument("--target-timestamp", required=True)
    parser.add_argument("--window", type=int, default=5)
    parser.add_argument("--input-file", default="./data/sysmon_logs_botsv1.json")
    parser.add_argument("--output-file", default="./reports/log_collector_result.json")
    
    args = parser.parse_args()
    res = collect_logs(args.dest_ip, args.target_timestamp, args.window, args.input_file)
    os.makedirs(os.path.dirname(os.path.abspath(args.output_file)), exist_ok=True)
    with open(args.output_file, 'w') as f: json.dump(res, f, indent=2)
    print(f"Log collection complete. Results saved to {args.output_file}")
