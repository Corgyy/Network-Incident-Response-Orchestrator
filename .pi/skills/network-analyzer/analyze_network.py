import json
import argparse
import sys
import subprocess
import os
import urllib.parse
import math
import statistics
from datetime import datetime, timedelta, timezone
from collections import Counter

def calculate_entropy(text):
    """Tính toán Shannon Entropy."""
    if not text or not isinstance(text, str): return 0
    text_len = len(text)
    if text_len == 0: return 0
    frequencies = Counter(text)
    entropy = -sum((count / text_len) * math.log2(count / text_len) for count in frequencies.values())
    return round(entropy, 4)

def calculate_symbol_density(text):
    """Tính toán mật độ ký tự đặc biệt."""
    if not text or not isinstance(text, str): return 0
    alnum_count = sum(1 for c in text if c.isalnum() or c in ['/', '.', '_', '-'])
    density = (len(text) - alnum_count) / (len(text) + 1e-9)
    return round(density, 4)

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
        norm_path = os.path.normpath(file_path)
        if os.name == 'nt':
            cmd = ["findstr", ioc, norm_path]
        else:
            cmd = ["grep", ioc, norm_path]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='ignore')
        for line in proc.stdout: yield line
        proc.wait()
    except Exception: pass

def get_iqr_threshold(data):
    """Tính ngưỡng Outlier dựa trên Interquartile Range (IQR)."""
    if len(data) < 4: return float('inf')
    sorted_data = sorted(data)
    q1 = statistics.median(sorted_data[:len(sorted_data)//2])
    q3 = statistics.median(sorted_data[len(sorted_data)//2:])
    iqr = q3 - q1
    return q3 + (1.5 * iqr)

def get_basename_and_ext(uri):
    """Trích xuất tên file và đuôi mở rộng từ URI."""
    if not uri: return "", ""
    try:
        path = urllib.parse.urlparse(uri).path
        basename = os.path.basename(path)
        ext = os.path.splitext(basename)[1].lower()
        return basename, ext
    except: pass
    return "", ""

def extract_subdomain(text):
    if not text: return ""
    try:
        hostname = text
        if "://" in text:
            hostname = urllib.parse.urlparse(text).hostname or text
        parts = hostname.split('.')
        if len(parts) > 2:
            return ".".join(parts[:-2])
    except: pass
    return ""

PORT_MAP = {
    "21": "FTP", "22": "SSH", "23": "Telnet", "25": "SMTP", "53": "DNS", "80": "HTTP", 
    "135": "RPC", "139": "NetBIOS", "443": "HTTPS", "445": "SMB", "3389": "RDP", 
    "8080": "HTTP-Proxy", "49152": "Dynamic-RPC", "49154": "MAPI"
}

def analyze_network(src_ip, target_timestamp_str, input_file="./data/network_streams_botsv1.json", window_minutes=5):
    if not os.path.exists(input_file): return {"error": f"File {input_file} not found"}
    target_time = parse_splunk_time(target_timestamp_str)
    start_window = target_time - timedelta(minutes=window_minutes)
    end_window = target_time + timedelta(minutes=window_minutes)
    
    # Pools for analysis
    all_flows = []
    domain_freq = Counter()
    uri_stats = Counter()
    ext_freq = Counter()
    port_stats = Counter()
    proto_data = {} # {proto: [bytes_out_list]}
    ip_history = {} # {dest_ip: {"times": [], "statuses": [], "bytes_out": []}}
    
    # First Pass: Collection
    for line in get_filtered_lines(input_file, src_ip):
        try:
            record = json.loads(line)
            data = record.get('result', record)
            raw = data.get('_raw')
            if raw and isinstance(raw, str) and raw.strip().startswith('{'):
                try: 
                    raw_data = json.loads(raw)
                    data.update(raw_data)
                except Exception: pass
            
            if data.get('src_ip') != src_ip and data.get('dest_ip') != src_ip: continue
            
            ts_str = data.get('timestamp') or data.get('_time')
            if not ts_str: continue
            current_time = parse_splunk_time(ts_str)
            if not (start_window <= current_time <= end_window): continue
            
            dest_ip = data.get('dest_ip')
            proto = data.get('app', data.get('protocol', 'unknown'))
            b_out = int(data.get('bytes_out', 0))
            
            # Nested HTTP object support
            http_info = data.get('http', {})
            if isinstance(http_info, str):
                try: http_info = json.loads(http_info)
                except: http_info = {}

            def get_single(val):
                if isinstance(val, list) and len(val) > 0: return str(val[0])
                return str(val) if val is not None else None

            status = get_single(data.get('status') or data.get('http_status') or http_info.get('status'))
            uri = get_single(data.get('uri') or data.get('url') or http_info.get('url') or http_info.get('uri'))
            query = get_single(data.get('query') or data.get('dns_query'))
            
            flow_item = {
                "time": ts_str, "dt": current_time, "dest": dest_ip, "port": data.get('dest_port'),
                "app": proto, "bytes_out": b_out, "status": status, "uri": uri, "query": query
            }
            
            all_flows.append(flow_item)
            if dest_ip not in ip_history: ip_history[dest_ip] = {"times": [], "statuses": [], "bytes_out": []}
            ip_history[dest_ip]["times"].append(current_time)
            ip_history[dest_ip]["bytes_out"].append(b_out)
            if status: ip_history[dest_ip]["statuses"].append(status)
            
            if proto not in proto_data: proto_data[proto] = []
            proto_data[proto].append(b_out)
            
            if uri: 
                uri_stats[uri] += 1
                domain = urllib.parse.urlparse(uri).netloc.split(':')[0]
                if domain: domain_freq[domain] += 1
                basename, ext = get_basename_and_ext(uri)
                if ext: ext_freq[ext] += 1
            if query: domain_freq[query.split('/')[0]] += 1
            if flow_item["port"]: port_stats[str(flow_item["port"])] += 1
            
        except Exception: continue

    if not all_flows: return {"status": "No flows found in window"}

    # Second Pass: Global Statistical Calculation
    total_flows = len(all_flows)
    proto_thresholds = {p: get_iqr_threshold(v) for p, v in proto_data.items()}
    
    # Calculate global consistency for Beaconing baseline
    all_std_devs = []
    for dip, history in ip_history.items():
        if len(history["times"]) >= 5:
            sorted_times = sorted(history["times"])
            deltas = [(sorted_times[i] - sorted_times[i-1]).total_seconds() for i in range(1, len(sorted_times))]
            all_std_devs.append(statistics.stdev(deltas) if len(deltas) > 1 else 999)
    
    global_std_dev_mean = statistics.mean(all_std_devs) if all_std_devs else 999
    
    # Third Pass: Dynamic Scoring
    suspicious_artifacts = []
    
    for dip, history in ip_history.items():
        # Idea 1: Beaconing (Z-Score based on global consistency)
        if len(history["times"]) >= 5:
            sorted_times = sorted(history["times"])
            deltas = [(sorted_times[i] - sorted_times[i-1]).total_seconds() for i in range(1, len(sorted_times))]
            ip_std_dev = statistics.stdev(deltas) if len(deltas) > 1 else 999
            
            # Nếu ip_std_dev thấp hơn đáng kể so với trung bình quần thể
            if ip_std_dev < global_std_dev_mean * 0.2: 
                score = 100 + (global_std_dev_mean / (ip_std_dev + 0.1))
                suspicious_artifacts.append({
                    "type": "C2_Beaconing", "value": dip, "score": round(min(score, 250), 1),
                    "context": f"Highly regular timing (IP StdDev: {round(ip_std_dev,3)} vs Global Mean: {round(global_std_dev_mean,3)})"
                })

        # Idea 3: Dynamic Error Rate (Outlier detection)
        if len(history["statuses"]) >= 5:
            error_count = sum(1 for s in history["statuses"] if str(s).startswith(('4', '5')))
            error_rate = error_count / len(history["statuses"])
            if error_rate > 0.7:
                suspicious_artifacts.append({
                    "type": "High_Error_Rate", "value": dip, "score": 100 + (error_rate * 100),
                    "context": f"Abnormal error frequency: {round(error_rate*100, 1)}%"
                })

    for f in all_flows:
        # Idea 2: Protocol-Aware Volume (IQR Based)
        threshold = proto_thresholds.get(f["app"], float('inf'))
        if f["bytes_out"] > threshold and f["bytes_out"] > 1024:
            p_name = PORT_MAP.get(str(f["port"]), f["app"])
            score = 100 + (f["bytes_out"] / (threshold + 1) * 10)
            suspicious_artifacts.append({
                "type": "Protocol_Volume_Outlier", "value": f"{f['dest']}:{f['port']} ({p_name})",
                "score": round(min(score, 200), 1),
                "context": f"Statistical volume outlier for {p_name} (Value: {f['bytes_out']} vs Threshold: {round(threshold,1)})"
            })

        # Idea 4: Rare Port (Frequency based)
        port_prob = port_stats[str(f["port"])] / total_flows
        if port_prob < 0.01: # Xuất hiện ít hơn 1%
            p_name = PORT_MAP.get(str(f["port"]), "Unknown")
            score = 50 + (1.0 / (port_prob + 0.001))
            suspicious_artifacts.append({
                "type": "Rare_Port", "value": f"{f['dest']}:{f['port']} ({p_name})",
                "score": round(min(score, 150), 1),
                "context": f"Anomalous port frequency: {round(port_prob*100, 3)}%"
            })

        # Idea 5: Subdomain Entropy (Baseline filter)
        for field in ["uri", "query"]:
            val = f.get(field)
            if val:
                sub = extract_subdomain(val)
                # Thay thế Hardcode Noise Filter bằng Frequency Filter
                # Nếu subdomain này xuất hiện quá phổ biến trong toàn bộ log (>5%), coi là baseline.
                sub_prob = domain_freq[sub] / total_flows if sub else 1.0
                if len(sub) > 8 and sub_prob < 0.02: 
                    ent = calculate_entropy(sub)
                    if ent > 3.8:
                        suspicious_artifacts.append({
                            "type": "High_Entropy_Subdomain", "value": sub, "score": 100 + (ent * 10),
                            "context": f"Complex subdomain (Entropy: {ent}, Pop: {round(sub_prob*100,2)}%)"
                        })

        # Idea 6: Re-integrate URI Statistical Scoring (Entropy & Density)
        if f.get("uri"):
            uri = f["uri"]
            rarity = 1.0 - (uri_stats[uri] / total_flows)
            if rarity > 0.95: # Chỉ xét các URI hiếm (xuất hiện < 5%)
                ent = calculate_entropy(uri)
                density = calculate_symbol_density(uri)
                
                # Điểm số động: Các URI cực dị sẽ có điểm rất cao
                if ent > 4.2 or density > 0.1:
                    score = 100 + (ent * 10) + (density * 100) + (rarity * 20)
                    suspicious_artifacts.append({
                        "type": "Suspicious_URI", "value": uri[:150], "score": round(min(score, 180), 1),
                        "context": f"Anomalous URI structure (Entropy: {ent}, Density: {density}, Pop: {round((1-rarity)*100, 3)}%)"
                    })

            # Idea 7 & 8: Basename Entropy & Rare Extension
            basename, ext = get_basename_and_ext(uri)
            
            if len(basename) > 5 and '.' in basename:
                base_name_only = os.path.splitext(basename)[0]
                base_ent = calculate_entropy(base_name_only)
                if base_ent > 3.5: # Basename entropy cao (dấu hiệu sinh ngẫu nhiên)
                    score = 100 + (base_ent * 20)
                    suspicious_artifacts.append({
                        "type": "Anomalous_Filename", "value": basename, "score": round(min(score, 190), 1),
                        "context": f"High entropy filename (Entropy: {base_ent})"
                    })
            
            if ext:
                ext_prob = ext_freq[ext] / total_flows
                if 0 < ext_prob < 0.0005: # Extension cực hiếm (< 0.05%)
                    score = 100 + (1.0 / (ext_prob + 0.0001))
                    suspicious_artifacts.append({
                        "type": "Rare_File_Extension", "value": f"{ext} in {uri[:50]}...", "score": round(min(score, 185), 1),
                        "context": f"Extremely rare extension (Pop: {round(ext_prob*100, 4)}%)"
                    })

    # Sort and Deduplicate
    unique_artifacts = {}
    for art in suspicious_artifacts:
        key = f"{art['type']}:{art['value']}"
        if key not in unique_artifacts or art["score"] > unique_artifacts[key]["score"]:
            unique_artifacts[key] = art
            
    sorted_artifacts = sorted(unique_artifacts.values(), key=lambda x: x["score"], reverse=True)
    
    # Dynamic Tiering
    critical_artifacts = []
    contextual_artifacts = []
    
    for art in sorted_artifacts:
        if art["score"] >= 150:
            critical_artifacts.append(art)
        elif art["score"] >= 100:
            if len(contextual_artifacts) < 100: # Safety cap for context
                contextual_artifacts.append(art)

    return {
        "feature_vector": {
            "flow_count": total_flows,
            "total_volume_mb": round(sum(f["bytes_out"] for f in all_flows) / (1024*1024), 4),
            "critical_artifact_count": len(critical_artifacts),
            "contextual_artifact_count": len(contextual_artifacts),
            "max_suspicion_score": sorted_artifacts[0]["score"] if sorted_artifacts else 0
        },
        "critical_findings": critical_artifacts,
        "contextual_findings": contextual_artifacts,
        "distinct_dest_ips": list(set(f["dest"] for f in all_flows if f["dest"]))
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="100% Statistical Network Anomaly Analyzer")
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
    print(f"[+] Statistical analysis complete. Results saved to {args.output_file}")
