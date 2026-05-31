#!/usr/bin/env python3
"""
TCP Stream Analyzer.
Đọc file PCAP qua tshark, thống kê TCP streams theo stream index.

Usage:
  python3 analyze_tcp.py --input <pcap_file> --output <tcp.json>
"""

import sys
import json
import subprocess
import argparse
import math
from pathlib import Path
from datetime import datetime
from collections import defaultdict, Counter


# ─── Helpers ────────────────────────────────────────────────────────

def safe_float(val, default=0.0) -> float:
    try:
        f = float(val)
        return f if math.isfinite(f) else default
    except (ValueError, TypeError):
        return default


def safe_int(val, default=0) -> int:
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


def check_tshark() -> bool:
    try:
        subprocess.run(
            ["tshark", "--version"],
            capture_output=True, timeout=5
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ─── tshark extraction ───────────────────────────────────────────────

FIELDS = [
    "tcp.stream",        # stream index (dùng để group)
    "ip.src",            # source IP
    "ip.dst",            # destination IP
    "tcp.srcport",       # source port
    "tcp.dstport",       # destination port
    "frame.len",         # frame length (bytes)
    "frame.time_epoch",  # timestamp
    "tcp.flags.syn",     # SYN flag
    "tcp.flags.fin",     # FIN flag
    "tcp.flags.reset",   # RST flag
    "tcp.flags.ack",     # ACK flag
    "ip.ttl",            # TTL
]


def extract_packets(pcap_path: str) -> list[dict]:
    """
    Chạy tshark -T fields để extract từng TCP packet.
    Trả về list các dict packet.
    """
    field_args = []
    for f in FIELDS:
        field_args += ["-e", f]

    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-E", "separator=|",
        "-E", "quote=n",
        "-E", "occurrence=f",
        "-Y", "tcp",            # chỉ lấy TCP packets
    ] + field_args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
    except subprocess.TimeoutExpired:
        print("[error] tshark timeout", file=sys.stderr)
        sys.exit(1)

    if result.returncode != 0 and not result.stdout:
        print(
            f"[error] tshark failed: {result.stderr[:300]}",
            file=sys.stderr
        )
        sys.exit(1)

    packets = []
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue

        parts = line.split('|')
        # Pad nếu thiếu field
        parts += [''] * (len(FIELDS) - len(parts))

        (stream_id, src_ip, dst_ip, src_port, dst_port,
         frame_len, ts, syn, fin, rst, ack, ttl) = parts[:12]

        # Bỏ qua packet không có stream id
        if not stream_id.strip():
            continue

        packets.append({
            "stream_id":  safe_int(stream_id, -1),
            "src_ip":     src_ip.strip(),
            "dst_ip":     dst_ip.strip(),
            "src_port":   safe_int(src_port),
            "dst_port":   safe_int(dst_port),
            "frame_len":  safe_int(frame_len),
            "ts":         safe_float(ts),
            "syn":        safe_int(syn),
            "fin":        safe_int(fin),
            "rst":        safe_int(rst),
            "ack":        safe_int(ack),
            "ttl":        safe_int(ttl),
        })

    return packets


# ─── Stream aggregation ──────────────────────────────────────────────

def determine_state(pkts: list[dict]) -> str:
    """
    Xác định trạng thái stream dựa trên TCP flags.
    - closed: có FIN hoặc RST
    - established: có SYN+ACK
    - open: chưa rõ
    """
    has_fin = any(p["fin"] for p in pkts)
    has_rst = any(p["rst"] for p in pkts)
    has_syn = any(p["syn"] for p in pkts)
    has_ack = any(p["ack"] for p in pkts)

    if has_fin or has_rst:
        return "closed"
    if has_syn and has_ack:
        return "established"
    return "open"


def classify_port(port: int) -> str:
    """Phân loại cổng theo mức độ quan tâm bảo mật."""
    HIGH_INTEREST = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        445: "smb", 1433: "mssql", 3306: "mysql",
        3389: "rdp", 5432: "postgres", 5900: "vnc",
        6379: "redis", 27017: "mongodb", 1524: "backdoor",
    }
    MEDIUM_INTEREST = {
        80: "http", 443: "https", 8080: "http-alt",
        8443: "https-alt", 110: "pop3", 143: "imap",
        993: "imaps", 995: "pop3s",
    }
    if port in HIGH_INTEREST:
        return HIGH_INTEREST[port]
    if port in MEDIUM_INTEREST:
        return MEDIUM_INTEREST[port]
    return "-"


def aggregate_streams(packets: list[dict]) -> list[dict]:
    """
    Gom packets theo tcp.stream index.
    Xác định chiều gửi/nhận theo packet đầu tiên của stream.
    """
    # Group theo stream_id
    by_stream: dict[int, list[dict]] = defaultdict(list)
    for pkt in packets:
        sid = pkt["stream_id"]
        if sid >= 0:
            by_stream[sid].append(pkt)

    streams = []
    for stream_id, pkts in sorted(by_stream.items()):
        # Sort theo timestamp
        pkts.sort(key=lambda p: p["ts"])
        first = pkts[0]

        # Chiều canonical: src→dst của packet đầu tiên
        src_ip   = first["src_ip"]
        dst_ip   = first["dst_ip"]
        src_port = first["src_port"]
        dst_port = first["dst_port"]

        # Phân chia forward / backward
        fwd = [p for p in pkts
               if p["src_ip"] == src_ip and p["dst_ip"] == dst_ip]
        bwd = [p for p in pkts
               if p["src_ip"] == dst_ip and p["dst_ip"] == src_ip]

        bytes_sent     = sum(p["frame_len"] for p in fwd)
        bytes_received = sum(p["frame_len"] for p in bwd)
        total_bytes    = bytes_sent + bytes_received

        # Timing
        start_ts = pkts[0]["ts"]
        end_ts   = pkts[-1]["ts"]
        duration = round(end_ts - start_ts, 6)

        # Throughput (bytes/sec)
        throughput = round(
            total_bytes / duration, 2
        ) if duration > 0 else 0.0

        service = classify_port(dst_port) or classify_port(src_port)

        streams.append({
            "stream_id":      stream_id,
            "src_ip":         src_ip,
            "dst_ip":         dst_ip,
            "src_port":       src_port,
            "dst_port":       dst_port,
            "service":        service,
            "packets":        len(pkts),
            "packets_sent":   len(fwd),
            "packets_recv":   len(bwd),
            "bytes_sent":     bytes_sent,
            "bytes_received": bytes_received,
            "total_bytes":    total_bytes,
            "duration":       duration,
            "throughput_bps": throughput,
            "start_time":     round(start_ts, 6),
            "end_time":       round(end_ts, 6),
            "state":          determine_state(pkts),
            "ttl":            first["ttl"],
        })

    return streams


# ─── Summary & security hints ────────────────────────────────────────

def compute_summary(streams: list[dict]) -> dict:
    """Tính các thống kê tổng hợp và gợi ý bảo mật."""
    if not streams:
        return {
            "total_streams":      0,
            "total_bytes_sent":   0,
            "total_bytes_received": 0,
            "total_bytes":        0,
            "closed_streams":     0,
            "open_streams":       0,
            "top_dst_ports":      {},
            "top_src_ips":        {},
            "top_dst_ips":        {},
            "high_interest_services": {},
            "security_hints":     [],
        }

    total_bytes_sent = sum(s["bytes_sent"] for s in streams)
    total_bytes_recv = sum(s["bytes_received"] for s in streams)

    dst_port_counts = Counter(s["dst_port"] for s in streams)
    src_ip_counts   = Counter(s["src_ip"] for s in streams)
    dst_ip_counts   = Counter(s["dst_ip"] for s in streams)

    # High-interest services
    hi_services: dict[str, int] = {}
    for s in streams:
        svc = s.get("service", "-")
        if svc and svc != "-":
            hi_services[svc] = hi_services.get(svc, 0) + 1

    # Security hints
    hints = []

    # Hint 1: Nhiều streams đến cùng dst_ip trong thời gian ngắn
    dst_ip_stream_count = Counter(s["dst_ip"] for s in streams)
    for ip, count in dst_ip_stream_count.items():
        if count > 20:
            hints.append({
                "type": "high_connection_count",
                "detail": f"{count} streams đến {ip} — "
                          f"có thể scanning hoặc DoS",
                "severity": "medium"
            })

    # Hint 2: RST nhiều — port scan hoặc connection refused
    rst_streams = [s for s in streams
                   if s["state"] == "closed"
                   and s["duration"] < 1.0
                   and s["packets"] <= 3]
    if len(rst_streams) > 10:
        hints.append({
            "type": "possible_port_scan",
            "detail": f"{len(rst_streams)} streams ngắn bị reset "
                      f"(< 1s, <= 3 packets) — có thể port scanning",
            "severity": "high"
        })

    # Hint 3: Lưu lượng lớn bất thường
    high_bw = [s for s in streams if s["throughput_bps"] > 10_000_000]
    for s in high_bw:
        hints.append({
            "type": "high_throughput",
            "detail": f"Stream {s['stream_id']}: "
                      f"{s['src_ip']}→{s['dst_ip']} "
                      f"throughput {s['throughput_bps']:,.0f} bps",
            "severity": "medium"
        })

    # Hint 4: Cổng nhạy cảm
    sensitive = ["telnet", "ftp", "backdoor", "vnc", "rdp"]
    for svc in sensitive:
        if svc in hi_services:
            hints.append({
                "type": "sensitive_service",
                "detail": f"Phát hiện {hi_services[svc]} streams "
                          f"sử dụng {svc.upper()} — "
                          f"kiểm tra xác thực và mã hóa",
                "severity": "high"
            })

    return {
        "total_streams":        len(streams),
        "total_bytes_sent":     total_bytes_sent,
        "total_bytes_received": total_bytes_recv,
        "total_bytes":          total_bytes_sent + total_bytes_recv,
        "closed_streams":       sum(1 for s in streams
                                    if s["state"] == "closed"),
        "open_streams":         sum(1 for s in streams
                                    if s["state"] != "closed"),
        "avg_duration":         round(
            sum(s["duration"] for s in streams) / len(streams), 3
        ),
        "top_dst_ports":        dict(dst_port_counts.most_common(10)),
        "top_src_ips":          dict(src_ip_counts.most_common(10)),
        "top_dst_ips":          dict(dst_ip_counts.most_common(10)),
        "high_interest_services": hi_services,
        "security_hints":       hints,
    }


# ─── Main ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Phân tích TCP streams từ PCAP"
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="Đường dẫn file PCAP"
    )
    parser.add_argument(
        "--output", "-o", required=True,
        help="Đường dẫn lưu tcp.json"
    )
    args = parser.parse_args()

    # Kiểm tra tshark
    if not check_tshark():
        print(json.dumps({
            "error": "tshark không tìm thấy. "
                     "Cài đặt: sudo apt install tshark"
        }))
        sys.exit(1)

    # Kiểm tra PCAP tồn tại
    if not Path(args.input).exists():
        print(json.dumps({
            "error": f"File PCAP không tồn tại: {args.input}"
        }))
        sys.exit(1)

    print(f"[*] Đọc PCAP: {args.input}", file=sys.stderr)
    packets = extract_packets(args.input)
    print(f"[*] Extracted {len(packets)} TCP packets", file=sys.stderr)

    if not packets:
        result = {
            "timestamp":   datetime.utcnow().isoformat(),
            "source_pcap": args.input,
            "summary": {
                "total_streams": 0,
                "security_hints": []
            },
            "streams": []
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(result, indent=2))
        print(json.dumps({"status": "ok", "total_streams": 0}))
        return

    print("[*] Aggregating TCP streams...", file=sys.stderr)
    streams = aggregate_streams(packets)
    print(f"[*] {len(streams)} TCP streams found", file=sys.stderr)

    summary = compute_summary(streams)

    result = {
        "timestamp":   datetime.utcnow().isoformat(),
        "source_pcap": args.input,
        "summary":     summary,
        "streams":     streams,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2))

    # In summary ra stdout cho agent đọc
    print(json.dumps({
        "status":        "ok",
        "total_streams": summary["total_streams"],
        "total_bytes":   summary["total_bytes"],
        "security_hints": len(summary["security_hints"]),
        "output":        args.output
    }, indent=2))

    print(
        f"[*] Saved {len(streams)} streams → {args.output}",
        file=sys.stderr
    )

    # In security hints ra stderr để agent thấy ngay
    if summary["security_hints"]:
        print("\n[!] Security hints:", file=sys.stderr)
        for h in summary["security_hints"]:
            print(
                f"    [{h['severity'].upper()}] {h['detail']}",
                file=sys.stderr
            )


if __name__ == "__main__":
    main()