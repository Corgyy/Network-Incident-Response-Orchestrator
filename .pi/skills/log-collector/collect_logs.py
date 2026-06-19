import argparse
import json
import os
import re
import subprocess
import base64
from datetime import datetime, timedelta, timezone
from collections import Counter

def load_config():
    config_path = "config.json"
    default_keywords = [
        "powershell", "cmd.exe", "certutil", "rundll32", "regsvr32", "wscript", 
        "schtasks", "wmic", "bitsadmin", "net.exe", "whoami", "tasklist", "vssadmin"
    ]
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                return json.load(f).get("suspicious_keywords", default_keywords)
        except Exception:
            return default_keywords
    return default_keywords

SUSPICIOUS_KEYWORDS = load_config()

def decode_powershell(command):
    """Phát hiện và giải mã PowerShell Base64 EncodedCommand."""
    if not command or not isinstance(command, str): return None
    # Tìm các flag phổ biến của PowerShell encoded command
    pattern = r'-(?:enc|encodedcommand|e|ec)\s+([A-Za-z0-9+/=]+)'
    match = re.search(pattern, command, re.IGNORECASE)
    if match:
        try:
            b64_str = match.group(1)
            decoded_bytes = base64.b64decode(b64_str)
            # PowerShell sử dụng UTF-16LE cho EncodedCommand
            decoded_text = decoded_bytes.decode('utf-16-le')
            return decoded_text
        except Exception:
            pass
    return None

def parse_time(value):
    if not value: return None
    value = str(value).strip().replace("Z", "+0000")
    if len(value) > 5 and (value[-5] in ['+', '-']) and value[-3] != ':':
        value = value[:-2] + ":" + value[-2:]
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo: return dt.astimezone(timezone.utc)
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        for fmt in ["%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"]:
            try:
                dt = datetime.strptime(value[:26] if '.' in value else value[:19], fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError: continue
    return None

def get_filtered_lines(file_path, keywords):
    try:
        normalized_path = os.path.normpath(file_path)
        if os.name == 'nt':
            # Windows: Dùng findstr /I /C:"kw1" /C:"kw2" ...
            chunk_size = 15
            for i in range(0, len(keywords), chunk_size):
                chunk = keywords[i:i + chunk_size]
                cmd = ["findstr", "/I"]
                for kw in chunk:
                    cmd.extend(["/C:" + kw])
                cmd.append(normalized_path)
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='ignore')
                for line in proc.stdout: yield line
                proc.wait()
        else:
            # Linux/macOS: Dùng grep
            pattern = "|".join([re.escape(k) for k in keywords])
            cmd = ["grep", "-i", "-E", pattern, file_path]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='ignore')
            for line in proc.stdout: yield line
            proc.wait()
        return
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
        "file_creation_events": [],
        "registry_persistence": [],
        "wmi_persistence": [],
        "hash_evidence": [],
        "unique_external_ips": set(),
        "all_hashes": set()
    }

    # Bổ sung từ khóa phát hiện Registry/WMI Persistence
    PERSISTENCE_KWS = ["CurrentVersion\\Run", "CurrentVersion\\Windows\\AppInit_DLLs", "WmiEvent", "ActiveScriptEventConsumer", "CommandLineEventConsumer"]
    SEARCH_KWS = list(set([dest_ip] + SUSPICIOUS_KEYWORDS + PERSISTENCE_KWS))

    for line in get_filtered_lines(input_file, SEARCH_KWS):
        try:
            record = json.loads(line)
            data = record.get('result', record)
            raw = data.get('_raw')
            
            # Extract fields from XML if necessary
            if raw and isinstance(raw, str):
                if raw.strip().startswith('{'):
                    try: data.update(json.loads(raw))
                    except json.JSONDecodeError: pass
                elif '<Event' in raw:
                    # Normalize escaped slashes often found in JSON-wrapped XML
                    raw_norm = raw.replace('\\/', '/')
                    
                    # Extract EventID
                    eid_match = re.search(r'<EventID>(.*?)</EventID>', raw_norm)
                    if eid_match: data['EventID'] = eid_match.group(1)
                    
                    # Extract EventData fields (Expanded for Persistence)
                    fields = ['UtcTime', 'Image', 'CommandLine', 'User', 'SourceIp', 'DestinationIp', 'DestinationPort', 
                              'Hashes', 'TargetFilename', 'ParentImage', 'ParentCommandLine', 'TargetObject', 'Details', 
                              'EventType', 'EventNamespace', 'Name', 'Query']
                    for field in fields:
                        f_match = re.search(f"<Data Name='{field}'>(.*?)</Data>", raw_norm)
                        if f_match: data[field] = f_match.group(1)

            ts_str = data.get('UtcTime') or data.get('timestamp') or data.get('_time')
            if not ts_str: continue
            curr_time = parse_time(ts_str)
            if not curr_time or not (start_window <= curr_time <= end_window): continue

            eid = str(data.get('EventID') or data.get('EventCode', ''))
            result["event_id_counter"][eid] += 1

            # Common hash extraction for all events
            hashes = data.get('Hashes', '')
            if hashes:
                h_dict = {h.split('=')[0]: h.split('=')[1] for h in hashes.split(',') if '=' in h}
                for h_val in h_dict.values():
                    result["all_hashes"].add(h_val)

            if eid == '1':
                cmd_line = data.get('CommandLine', '').lower()
                image = data.get('Image', '').lower()
                parent_image = data.get('ParentImage', '').lower()
                parent_cmd = data.get('ParentCommandLine', '').lower()
                
                if any(kw in cmd_line or kw in image or kw in parent_image or kw in parent_cmd for kw in SUSPICIOUS_KEYWORDS):
                    # Smart PowerShell Decoding
                    decoded = decode_powershell(data.get('CommandLine'))
                    
                    # Extract hashes for the process entry
                    h_dict = {}
                    if hashes:
                        h_dict = {h.split('=')[0]: h.split('=')[1] for h in hashes.split(',') if '=' in h}
                        
                    ev = {
                        "time": ts_str, 
                        "image": data.get('Image'), 
                        "command_line": data.get('CommandLine'), 
                        "user": data.get('User'), 
                        "parent_image": data.get('ParentImage'),
                        "decoded_command": decoded,
                        "hashes": h_dict
                    }
                    result["suspicious_processes"].append(ev)
                    result["suspicious_commands"].append(ev)
                    if h_dict:
                        result["hash_evidence"].append({"image": data.get('Image'), "hashes": h_dict})
            
            elif eid == '3':
                src_ip = data.get('SourceIp')
                dst_ip_val = data.get('DestinationIp')
                if src_ip == dest_ip or dst_ip_val == dest_ip:
                    result["network_connections"].append({"time": ts_str, "image": data.get('Image'), "destination_ip": dst_ip_val, "destination_port": data.get('DestinationPort')})
                    other_ip = dst_ip_val if src_ip == dest_ip else src_ip
                    if other_ip and other_ip != dest_ip:
                        result["unique_external_ips"].add(other_ip)

            elif eid == '11':
                result["file_creation_events"].append({"time": ts_str, "image": data.get('Image'), "target_filename": data.get('TargetFilename'), "user": data.get('User')})

            elif eid in ['12', '13', '14']:
                # Registry Persistence
                target_obj = data.get('TargetObject', '')
                if any(kw in target_obj for kw in ["CurrentVersion\\Run", "CurrentVersion\\Windows\\AppInit_DLLs"]):
                    result["registry_persistence"].append({
                        "time": ts_str, "event": eid, "image": data.get('Image'), 
                        "target_object": target_obj, "details": data.get('Details')
                    })

            elif eid in ['19', '20', '21']:
                # WMI Persistence
                result["wmi_persistence"].append({
                    "time": ts_str, "event": eid, "name": data.get('Name'), 
                    "query": data.get('Query'), "operation": data.get('EventType')
                })

        except Exception: continue

    result["event_id_counter"] = dict(result["event_id_counter"])
    result["unique_external_ips"] = [ip for ip in result["unique_external_ips"]]
    result["all_hashes"] = [h for h in result["all_hashes"]]
    result["risk_level"] = "high" if result["suspicious_commands"] or result["file_creation_events"] or result["registry_persistence"] or result["wmi_persistence"] else "low"
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
