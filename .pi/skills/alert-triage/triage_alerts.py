import argparse
import json
import os
from collections import Counter
from datetime import datetime, timezone

def parse_time(value):
    """Hàm chuẩn hóa thời gian về dạng datetime object - Hỗ trợ múi giờ"""
    if not value:
        return None
    value = str(value).strip().replace("Z", "+0000")
    
    # Hỗ trợ định dạng offset Splunk (+0700 -> +07:00)
    if len(value) > 5 and (value[-5] in ['+', '-']) and value[-3] != ':':
        value = value[:-2] + ":" + value[-2:]
        
    try:
        # Sử dụng fromisoformat (Python 3.7+) rất mạnh mẽ
        dt = datetime.fromisoformat(value)
        if dt.tzinfo:
            return dt.astimezone(timezone.utc)
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        formats = [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S"
        ]
        for fmt in formats:
            try:
                # Fallback cho các định dạng không có offset
                dt = datetime.strptime(value[:26] if '.' in value else value[:19], fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None

def search_in_file(file_path, ioc_lower):
    """Tìm kiếm IOC trong file và parse JSON records - Optimized"""
    matches = []
    if not os.path.exists(file_path):
        return matches
        
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if ioc_lower in line.lower():
                try:
                    record = json.loads(line)
                    data = record.get('result', record)
                    raw = data.get('_raw')
                    if raw and isinstance(raw, str):
                        raw_s = raw.strip()
                        if raw_s.startswith('{'):
                            try:
                                data.update(json.loads(raw_s))
                            except json.JSONDecodeError: pass
                    matches.append(data)
                except json.JSONDecodeError:
                    continue
    return matches

def get_file_timerange(file_path):
    """Lấy mốc thời gian mẫu của file log để kiểm tra tính hợp lệ (Không giả định file đã sort)"""
    if not os.path.exists(file_path): return None, None
    found_ts = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Đọc 100 dòng đầu để lấy mẫu thời gian
            for _ in range(100):
                line = f.readline()
                if not line: break
                try:
                    data = json.loads(line).get('result', json.loads(line))
                    ts_str = data.get('timestamp') or data.get('_time') or data.get('UtcTime')
                    ts_obj = parse_time(ts_str)
                    if ts_obj: found_ts.append(ts_obj)
                except: continue
    except Exception: pass
    
    if not found_ts: return None, None
    return min(found_ts), max(found_ts)

def main():
    parser = argparse.ArgumentParser(description="Alert Triage Agent - Step 0 (Standardized Paths)")
    parser.add_argument("--ioc", required=True, help="Indicator of compromise")
    parser.add_argument("--alert-file", default="./data/alerts_trigger_botsv1.json", help="Path to alerts file")
    parser.add_argument("--sysmon-file", default="./data/sysmon_logs_botsv1.json", help="Path to sysmon file")
    parser.add_argument("--output-file", default="./reports/triage_context.json", help="Path to save triage context JSON")
    args = parser.parse_args()

    ioc_lower = args.ioc.lower()
    
    # BƯỚC 1: Tìm trong Alert File
    matched_records = search_in_file(args.alert_file, ioc_lower)
    source_used = "Alerts"
    
    # BƯỚC 2: Fallback to Sysmon
    if not matched_records:
        matched_records = search_in_file(args.sysmon_file, ioc_lower)
        source_used = "Sysmon"

    if not matched_records:
        print(json.dumps({"error": f"No alerts found for IOC '{args.ioc}'."}))
        return

    # BƯỚC 3: Analytics
    src_ips = Counter()
    dest_ips = Counter()
    signatures = Counter()
    timestamps = []
    warnings = []

    for data in matched_records:
        src = data.get('src_ip') or data.get('SourceIp') or data.get('src')
        dst = data.get('dest_ip') or data.get('DestinationIp') or data.get('dest')
        if src: src_ips[src] += 1
        if dst: dest_ips[dst] += 1
        
        sig = "Unknown"
        if source_used == "Alerts":
            alert = data.get('alert', {})
            sig = alert.get('signature') if isinstance(alert, dict) else data.get('signature', "Unknown Alert")
        else:
            eid = data.get('EventID') or data.get('EventCode')
            sig = f"Sysmon EID {eid}" if eid else "Host Activity"
        signatures[sig] += 1
            
        ts_str = data.get('timestamp') or data.get('_time') or data.get('UtcTime')
        if ts_str:
            ts_obj = parse_time(ts_str)
            if ts_obj: timestamps.append((ts_obj, ts_str))

    attacker_ip = src_ips.most_common(1)[0][0] if src_ips else "Unknown"
    victim_ip = dest_ips.most_common(1)[0][0] if dest_ips else "Unknown"
    
    if args.ioc == attacker_ip and dest_ips: victim_ip = dest_ips.most_common(1)[0][0]
    elif args.ioc == victim_ip and src_ips: attacker_ip = src_ips.most_common(1)[0][0]
    
    first_seen_str = "Unknown"
    duration_minutes = 0
    recommended_window = 10
    
    if timestamps:
        timestamps.sort(key=lambda x: x[0])
        first_seen_obj = timestamps[0][0]
        first_seen_str = timestamps[0][1]
        duration = timestamps[-1][0] - timestamps[0][0]
        duration_minutes = int(duration.total_seconds() / 60)
        recommended_window = duration_minutes + 10

        # TIME DRIFT DETECTION (New in V4)
        sysmon_start, sysmon_end = get_file_timerange(args.sysmon_file)
        if sysmon_start and abs((sysmon_start - first_seen_obj).days) > 1:
            warnings.append(f"CRITICAL TIME MISMATCH: Alerts are from {first_seen_obj.date()}, but Sysmon logs are from {sysmon_start.date()}. Log collection will likely return 0 results.")

    if len(matched_records) > 2000:
        warnings.append("High Noise: Too many matches, consider a more specific IOC.")

    output = {
        "ioc_investigated": args.ioc,
        "source_data": source_used,
        "matched_records_count": len(matched_records),
        "warnings": warnings,
        "inferred_entities": {"attacker_ip": attacker_ip, "victim_ip": victim_ip},
        "timeline": {
            "first_seen": first_seen_str,
            "duration_minutes": duration_minutes,
            "recommended_window_minutes": recommended_window
        },
        "next_steps_guide": {
            "log_collector_args": f"--dest-ip {victim_ip} --target-timestamp \"{first_seen_str}\" --window {recommended_window} --output-file ./reports/log_collector_result.json",
            "network_analyzer_args": f"--src-ip {attacker_ip} --target-timestamp \"{first_seen_str}\" --window {recommended_window} --output-file ./reports/network_analyzer_result.json"
        }
    }
    
    # Lưu kết quả vào file
    os.makedirs(os.path.dirname(os.path.abspath(args.output_file)), exist_ok=True)
    with open(args.output_file, 'w', encoding='utf-8') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
        
    print(json.dumps(output, indent=2))

if __name__ == "__main__":
    main()
