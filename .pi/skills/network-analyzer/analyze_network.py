import json
import argparse
import sys
import subprocess
import os
from datetime import datetime, timedelta, timezone

def parse_splunk_time(time_str):
    if not time_str: return None
    t_str = str(time_str).strip().replace('Z', '+00:00')
    if len(t_str) > 5 and (t_str[-5] in ['+', '-']) and t_str[-3] != ':':
        t_str = t_str[:-2] + ':' + t_str[-2:]
    try:
        dt = datetime.fromisoformat(t_str)
        if dt.tzinfo: return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt.replace(tzinfo=None)
    except Exception:
        return datetime.strptime(t_str[:19], "%Y-%m-%dT%H:%M:%S")

def get_filtered_lines(file_path, ioc):
    try:
        cmd = ["grep", ioc, file_path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='ignore')
        for line in proc.stdout: yield line
        proc.wait()
        if proc.returncode == 0: return
    except Exception: pass
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if ioc in line: yield line

def analyze_network(src_ip, target_timestamp_str, input_file="./data/network_streams_botsv1.json", window_minutes=5):
    if not os.path.exists(input_file): return {"error": f"File {input_file} not found"}
    target_time = parse_splunk_time(target_timestamp_str)
    start_window = target_time - timedelta(minutes=window_minutes)
    end_window = target_time + timedelta(minutes=window_minutes)
    stats = {"total_bytes": 0, "bytes_in": 0, "bytes_out": 0, "packets_in": 0, "packets_out": 0, "protocols": {}, "flow_count": 0, "distinct_dest_ips": set()}

    for line in get_filtered_lines(input_file, src_ip):
        try:
            record = json.loads(line)
            data = record.get('result', record)
            raw = data.get('_raw')
            if raw and isinstance(raw, str) and raw.strip().startswith('{'):
                try: data.update(json.loads(raw))
                except Exception: pass
            if data.get('src_ip') != src_ip and data.get('dest_ip') != src_ip: continue
            current_time_str = data.get('timestamp') or data.get('_time')
            if not current_time_str: continue
            current_time = parse_splunk_time(current_time_str)
            if not (start_window <= current_time <= end_window): continue
            stats["flow_count"] += 1
            stats["total_bytes"] += int(data.get('bytes', 0))
            stats["bytes_in"] += int(data.get('bytes_in', 0))
            stats["bytes_out"] += int(data.get('bytes_out', 0))
            stats["packets_in"] += int(data.get('packets_in', 0))
            stats["packets_out"] += int(data.get('packets_out', 0))
            proto = data.get('app', data.get('protocol', 'unknown'))
            stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
            dest_ip = data.get('dest_ip')
            if dest_ip: stats["distinct_dest_ips"].add(dest_ip)
        except Exception: continue

    feature_vector = {
        "flow_count": stats["flow_count"],
        "total_volume_mb": round(stats["total_bytes"] / (1024*1024), 4),
        "in_out_ratio": round(stats["bytes_out"] / (stats["bytes_in"] + 1e-9), 4),
        "packet_rate": round((stats["packets_in"] + stats["packets_out"]) / (window_minutes * 120.0), 4),
        "distinct_protocols_count": len(stats["protocols"]),
        "distinct_dest_count": len(stats["distinct_dest_ips"]),
        "top_protocol": max(stats["protocols"], key=stats["protocols"].get) if stats["protocols"] else "none"
    }
    return {"feature_vector": feature_vector, "analysis_summary": f"Analyzed {stats['flow_count']} flows for {src_ip}."}

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze network streams (Grep-First)")
    parser.add_argument("--src-ip", required=True)
    parser.add_argument("--target-timestamp", required=True)
    parser.add_argument("--input-file", default="./data/network_streams_botsv1.json")
    parser.add_argument("--output-file", default="./reports/network_analyzer_result.json")
    parser.add_argument("--window", type=int, default=5)
    
    args = parser.parse_args()
    result = analyze_network(args.src_ip, args.target_timestamp, args.input_file, args.window)
    
    os.makedirs(os.path.dirname(os.path.abspath(args.output_file)), exist_ok=True)
    with open(args.output_file, 'w') as f:
        json.dump(result, f, indent=2)
    
    print(f"Network analysis complete. Results saved to {args.output_file}")
