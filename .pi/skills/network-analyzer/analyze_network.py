import json
import sys
from datetime import datetime, timedelta
import os

def parse_splunk_time(time_str):
    """Parses Splunk/ISO 8601 timestamp formats."""
    # Common format in BOTSv1: 2016-08-24T18:27:32.732845Z
    try:
        # Strip micro/nano seconds for easier parsing if needed, or use fromisoformat
        clean_time = time_str.split('.')[0].replace('Z', '')
        return datetime.fromisoformat(clean_time)
    except Exception:
        # Fallback for other formats
        return datetime.strptime(time_str[:19], "%Y-%m-%dT%H:%M:%S")

def analyze_network(src_ip, target_timestamp_str, input_file):
    if not os.path.exists(input_file):
        return {"error": f"File {input_file} not found"}

    target_time = parse_splunk_time(target_timestamp_str)
    start_window = target_time - timedelta(minutes=5)
    end_window = target_time + timedelta(minutes=5)

    stats = {
        "total_bytes": 0,
        "bytes_in": 0,
        "bytes_out": 0,
        "packets_in": 0,
        "packets_out": 0,
        "protocols": {},
        "flow_count": 0,
        "durations": [],
        "distinct_dest_ips": set()
    }

    try:
        with open(input_file, 'r') as f:
            for line in f:
                try:
                    record = json.loads(line)
                    # Splunk export structure: usually {"result": {...}}
                    data = record.get('result', record)
                    
                    # 1. Filter by IP
                    if data.get('src_ip') != src_ip and data.get('dest_ip') != src_ip:
                        continue
                    
                    # 2. Filter by Time Window
                    current_time_str = data.get('timestamp') or data.get('_time')
                    if not current_time_str:
                        continue
                    
                    current_time = parse_splunk_time(current_time_str)
                    if not (start_window <= current_time <= end_window):
                        continue

                    # 3. Aggregate Features
                    stats["flow_count"] += 1
                    stats["total_bytes"] += int(data.get('bytes', 0))
                    stats["bytes_in"] += int(data.get('bytes_in', 0))
                    stats["bytes_out"] += int(data.get('bytes_out', 0))
                    stats["packets_in"] += int(data.get('packets_in', 0))
                    stats["packets_out"] += int(data.get('packets_out', 0))
                    
                    # Protocols (app)
                    proto = data.get('app', data.get('protocol', 'unknown'))
                    stats["protocols"][proto] = stats["protocols"].get(proto, 0) + 1
                    
                    # Destinations
                    dest_ip = data.get('dest_ip')
                    if dest_ip:
                        stats["distinct_dest_ips"].add(dest_ip)

                except (json.JSONDecodeError, ValueError):
                    continue
    except Exception as e:
        return {"error": str(e)}

    # Final calculations
    avg_duration = 0 # Need time_taken or endtime - starttime logic if available
    
    feature_vector = {
        "flow_count": stats["flow_count"],
        "total_volume_mb": round(stats["total_bytes"] / (1024*1024), 4),
        "in_out_ratio": round(stats["bytes_out"] / (stats["bytes_in"] + 1e-9), 4),
        "packet_rate": round((stats["packets_in"] + stats["packets_out"]) / 600.0, 4), # Over 10 min window
        "distinct_protocols_count": len(stats["protocols"]),
        "distinct_dest_count": len(stats["distinct_dest_ips"]),
        "top_protocol": max(stats["protocols"], key=stats["protocols"].get) if stats["protocols"] else "none"
    }

    summary = (f"Analysis of IP {src_ip} around {target_timestamp_str} shows {stats['flow_count']} flows. "
               f"Total data: {feature_vector['total_volume_mb']} MB. "
               f"Primary protocol observed: {feature_vector['top_protocol']}. "
               f"The IP communicated with {feature_vector['distinct_dest_count']} distinct destinations.")

    return {
        "feature_vector": feature_vector,
        "analysis_summary": summary
    }

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Missing arguments. Usage: python analyze_network.py <src_ip> <timestamp> [input_file]"}))
        sys.exit(1)
    
    src_ip = sys.argv[1]
    timestamp = sys.argv[2]
    input_file = sys.argv[3] if len(sys.argv) > 3 else "input_data/network_streams_botsv1.json"
    
    result = analyze_network(src_ip, timestamp, input_file)
    print(json.dumps(result, indent=2))
