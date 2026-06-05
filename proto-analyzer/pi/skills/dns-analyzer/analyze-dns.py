#!/usr/bin/env python3
"""
DNS Flow Analyzer.
Đọc file PCAP qua tshark, lọc UDP port 53, thống kê DNS queries/responses.
Phát hiện suspicious domains dựa trên entropy và đặc điểm bất thường.

Usage:
  python3 analyze_dns.py --input <pcap_file> --output <dns.json>
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

def safe_int(val, default=0) -> int:
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return default


def safe_float(val, default=0.0) -> float:
    try:
        f = float(val)
        return f if math.isfinite(f) else default
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


# ─── Domain analysis ─────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """
    Tính Shannon entropy của chuỗi.
    Entropy cao (> 3.5) thường gặp ở DGA domains.
    """
    if not s:
        return 0.0
    freq = Counter(s.lower())
    n = len(s)
    return -sum(
        (c / n) * math.log2(c / n)
        for c in freq.values()
    )


def get_tld(domain: str) -> str:
    """Lấy TLD (phần cuối sau dấu chấm cuối cùng)."""
    parts = domain.rstrip('.').split('.')
    return parts[-1].lower() if parts else ""


def get_registered_domain(domain: str) -> str:
    """Lấy registered domain (2 phần cuối): sub.example.com → example.com"""
    parts = domain.rstrip('.').split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:]).lower()
    return domain.lower()


# TLD đáng ngờ thường gặp trong malware/phishing
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",   # Freenom TLDs — hay bị lạm dụng
    "ru", "cn", "top", "xyz", "pw",
    "cc", "ws", "biz", "info",
}

# Query types phổ biến
QTYPE_MAP = {
    "1":  "A",
    "2":  "NS",
    "5":  "CNAME",
    "6":  "SOA",
    "12": "PTR",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "33": "SRV",
    "255": "ANY",
}

# Response codes
RCODE_MAP = {
    "0": "NOERROR",
    "1": "FORMERR",
    "2": "SERVFAIL",
    "3": "NXDOMAIN",
    "4": "NOTIMP",
    "5": "REFUSED",
}


def is_suspicious_domain(domain: str) -> tuple[bool, list[str]]:
    """
    Kiểm tra domain có đáng ngờ không.
    Trả về (is_suspicious, danh sách lý do).
    """
    reasons = []
    domain_clean = domain.rstrip('.').lower()

    # Bỏ qua reverse DNS lookups
    if domain_clean.endswith(".in-addr.arpa") or \
       domain_clean.endswith(".ip6.arpa"):
        return False, []

    # 1. Entropy cao → DGA candidate
    # Chỉ tính entropy trên phần subdomain/hostname, bỏ TLD
    parts = domain_clean.split('.')
    hostname = parts[0] if parts else domain_clean
    entropy = shannon_entropy(hostname)
    if entropy > 3.5 and len(hostname) > 8:
        reasons.append(
            f"entropy cao ({entropy:.2f}) — DGA candidate"
        )

    # 2. Tên miền quá dài
    if len(domain_clean) > 50:
        reasons.append(
            f"domain dài bất thường ({len(domain_clean)} ký tự)"
        )

    # 3. Subdomain quá dài (có thể DNS tunneling)
    if len(hostname) > 30:
        reasons.append(
            f"subdomain dài ({len(hostname)} ký tự) — "
            f"có thể DNS tunneling"
        )

    # 4. Nhiều chữ số trong hostname
    digit_ratio = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    if digit_ratio > 0.4 and len(hostname) > 6:
        reasons.append(
            f"tỉ lệ chữ số cao ({digit_ratio:.0%}) trong hostname"
        )

    # 5. TLD đáng ngờ
    tld = get_tld(domain_clean)
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"TLD đáng ngờ: .{tld}")

    # 6. Nhiều dấu gạch ngang
    if hostname.count('-') > 3:
        reasons.append(
            f"nhiều dấu gạch ngang ({hostname.count('-')}) trong hostname"
        )

    # 7. Toàn ký tự hex (DGA pattern)
    hex_chars = set('0123456789abcdef')
    if len(hostname) >= 8 and all(c in hex_chars for c in hostname):
        reasons.append("hostname chỉ gồm ký tự hex — DGA pattern")

    return len(reasons) > 0, reasons


# ─── tshark extraction ───────────────────────────────────────────────

DNS_FIELDS = [
    "frame.time_epoch",      # timestamp
    "ip.src",                # source IP
    "ip.dst",                # destination IP
    "dns.id",                # transaction ID
    "dns.flags.response",    # 0=query, 1=response
    "dns.qry.name",          # query name
    "dns.qry.type",          # query type (số)
    "dns.resp.name",         # response name
    "dns.a",                 # A record IP (nếu có)
    "dns.flags.rcode",       # response code
    "dns.count.answers",     # số answers
    "frame.len",             # frame length
]


def extract_dns_packets(pcap_path: str) -> list[dict]:
    """
    Extract DNS packets từ PCAP bằng tshark.
    Filter: udp.port == 53
    """
    field_args = []
    for f in DNS_FIELDS:
        field_args += ["-e", f]

    cmd = [
        "tshark",
        "-r", pcap_path,
        "-T", "fields",
        "-E", "separator=|",
        "-E", "quote=n",
        "-E", "occurrence=f",
        "-Y", "udp.port == 53",
    ] + field_args

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
    except subprocess.TimeoutExpired:
        print("[error] tshark timeout khi đọc DNS", file=sys.stderr)
        sys.exit(1)

    packets = []
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue

        parts = line.split('|')
        parts += [''] * (len(DNS_FIELDS) - len(parts))

        (ts, src_ip, dst_ip, dns_id, is_response,
         qry_name, qry_type, resp_name, resp_a,
         rcode, answer_count, frame_len) = parts[:12]

        packets.append({
            "ts":           safe_float(ts),
            "src_ip":       src_ip.strip(),
            "dst_ip":       dst_ip.strip(),
            "dns_id":       dns_id.strip(),
            "is_response":  safe_int(is_response) == 1,
            "qry_name":     qry_name.strip().rstrip('.'),
            "qry_type":     QTYPE_MAP.get(
                                qry_type.strip(), qry_type.strip()
                            ),
            "resp_name":    resp_name.strip().rstrip('.'),
            "resp_a":       [
                                ip.strip()
                                for ip in resp_a.split(',')
                                if ip.strip()
                            ] if resp_a.strip() else [],
            "rcode":        RCODE_MAP.get(
                                rcode.strip(), rcode.strip()
                            ),
            "answer_count": safe_int(answer_count),
            "frame_len":    safe_int(frame_len),
        })

    return packets


# ─── Flow matching & aggregation ────────────────────────────────────

def match_queries_responses(
    packets: list[dict]
) -> list[dict]:
    """
    Match DNS queries với responses theo transaction ID + src/dst IP pair.
    Trả về list các DNS flow đã ghép cặp.
    """
    # queries: key = (dns_id, client_ip, server_ip)
    queries: dict[tuple, dict] = {}
    flows: list[dict] = []

    for pkt in sorted(packets, key=lambda p: p["ts"]):
        if not pkt["is_response"]:
            # Đây là query
            key = (pkt["dns_id"], pkt["src_ip"], pkt["dst_ip"])
            queries[key] = pkt
        else:
            # Đây là response — tìm query tương ứng
            # Response: src=server, dst=client → đảo key
            key = (pkt["dns_id"], pkt["dst_ip"], pkt["src_ip"])
            query = queries.pop(key, None)

            flow = {
                "query_id":      pkt["dns_id"],
                "client_ip":     pkt["dst_ip"],
                "server_ip":     pkt["src_ip"],
                "query_name":    pkt["resp_name"] or (
                    query["qry_name"] if query else ""
                ),
                "query_type":    query["qry_type"] if query else "unknown",
                "response_code": pkt["rcode"],
                "response_ips":  pkt["resp_a"],
                "answer_count":  pkt["answer_count"],
                "timestamp":     datetime.utcfromtimestamp(
                    pkt["ts"]
                ).isoformat(),
                "latency_ms":    round(
                    (pkt["ts"] - query["ts"]) * 1000, 2
                ) if query else None,
                "matched":       query is not None,
            }
            flows.append(flow)

    # Queries không có response (timeout hoặc chưa nhận được)
    for key, query in queries.items():
        flows.append({
            "query_id":      query["dns_id"],
            "client_ip":     query["src_ip"],
            "server_ip":     query["dst_ip"],
            "query_name":    query["qry_name"],
            "query_type":    query["qry_type"],
            "response_code": "NO_RESPONSE",
            "response_ips":  [],
            "answer_count":  0,
            "timestamp":     datetime.utcfromtimestamp(
                query["ts"]
            ).isoformat(),
            "latency_ms":    None,
            "matched":       False,
        })

    return sorted(flows, key=lambda f: f["timestamp"])


# ─── Suspicious domain detection ────────────────────────────────────

def detect_suspicious(flows: list[dict]) -> list[dict]:
    """
    Phát hiện suspicious domains từ danh sách flows.
    Group theo domain để tính query_count.
    """
    domain_flows: dict[str, list[dict]] = defaultdict(list)
    for f in flows:
        name = f.get("query_name", "")
        if name:
            domain_flows[name].append(f)

    suspicious = []
    for domain, domain_flow_list in domain_flows.items():
        is_susp, reasons = is_suspicious_domain(domain)
        if is_susp:
            # Lấy unique client IPs
            clients = list({f["client_ip"] for f in domain_flow_list})
            suspicious.append({
                "domain":       domain,
                "reasons":      reasons,
                "query_count":  len(domain_flow_list),
                "unique_clients": clients,
                "query_types":  list({
                    f["query_type"] for f in domain_flow_list
                }),
                "severity":     "high" if len(reasons) >= 2 else "medium",
            })

    return sorted(suspicious, key=lambda x: -x["query_count"])


# ─── Summary ─────────────────────────────────────────────────────────

def compute_summary(
    packets: list[dict],
    flows: list[dict],
    suspicious: list[dict]
) -> dict:
    queries   = [p for p in packets if not p["is_response"]]
    responses = [p for p in packets if p["is_response"]]

    # Query type distribution
    qtype_counts = Counter(
        q["qry_type"] for q in queries if q["qry_type"]
    )

    # Response code distribution
    rcode_counts = Counter(
        f["response_code"] for f in flows if f["matched"]
    )

    # Top queried domains (registered domain level)
    domain_counts = Counter(
        get_registered_domain(f["query_name"])
        for f in flows
        if f.get("query_name")
    )

    # Top DNS servers được dùng
    server_counts = Counter(
        f["server_ip"] for f in flows if f.get("server_ip")
    )

    # Latency stats (chỉ tính flows có response)
    latencies = [
        f["latency_ms"] for f in flows
        if f.get("latency_ms") is not None and f["latency_ms"] >= 0
    ]
    avg_latency = round(sum(latencies) / len(latencies), 2) \
        if latencies else None

    # No-response queries
    no_response = [f for f in flows if not f["matched"]]

    # Unique domains
    unique_domains = len({
        get_registered_domain(f["query_name"])
        for f in flows
        if f.get("query_name")
    })

    # Security hints
    hints = []

    if len(suspicious) > 0:
        high_sev = [s for s in suspicious if s["severity"] == "high"]
        hints.append({
            "type": "suspicious_domains",
            "detail": f"{len(suspicious)} suspicious domains "
                      f"({len(high_sev)} high severity)",
            "severity": "high" if high_sev else "medium"
        })

    nxdomain_count = rcode_counts.get("NXDOMAIN", 0)
    if nxdomain_count > 20:
        hints.append({
            "type": "high_nxdomain",
            "detail": f"{nxdomain_count} NXDOMAIN responses — "
                      f"có thể DGA hoặc misconfiguration",
            "severity": "medium"
        })

    if len(no_response) > len(flows) * 0.3 and len(flows) > 10:
        hints.append({
            "type": "high_no_response",
            "detail": f"{len(no_response)}/{len(flows)} queries "
                      f"không có response — "
                      f"có thể DNS filtering hoặc packet loss",
            "severity": "low"
        })

    # Kiểm tra DNS tunneling: latency cao bất thường
    if latencies:
        high_lat = [l for l in latencies if l > 2000]
        if high_lat:
            hints.append({
                "type": "high_dns_latency",
                "detail": f"{len(high_lat)} queries có latency > 2s — "
                          f"có thể DNS tunneling hoặc slow resolver",
                "severity": "medium"
            })

    return {
        "total_dns_packets":    len(packets),
        "total_queries":        len(queries),
        "total_responses":      len(responses),
        "matched_flows":        sum(1 for f in flows if f["matched"]),
        "unmatched_queries":    len(no_response),
        "unique_domains":       unique_domains,
        "avg_latency_ms":       avg_latency,
        "query_types":          dict(qtype_counts.most_common()),
        "response_codes":       dict(rcode_counts.most_common()),
        "top_queried_domains":  dict(domain_counts.most_common(15)),
        "top_dns_servers":      dict(server_counts.most_common(5)),
        "suspicious_count":     len(suspicious),
        "security_hints":       hints,
    }


# ─── Main ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Phân tích DNS flows từ PCAP"
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="Đường dẫn file PCAP"
    )
    parser.add_argument(
        "--output", "-o", required=True,
        help="Đường dẫn lưu dns.json"
    )
    args = parser.parse_args()

    # Kiểm tra tshark
    if not check_tshark():
        print(json.dumps({
            "error": "tshark không tìm thấy. "
                     "Cài đặt: sudo apt install tshark"
        }))
        sys.exit(1)

    # Kiểm tra PCAP
    if not Path(args.input).exists():
        print(json.dumps({
            "error": f"File PCAP không tồn tại: {args.input}"
        }))
        sys.exit(1)

    print(f"[*] Đọc DNS packets từ: {args.input}", file=sys.stderr)
    packets = extract_dns_packets(args.input)
    print(f"[*] {len(packets)} DNS packets extracted", file=sys.stderr)

    if not packets:
        result = {
            "timestamp":   datetime.utcnow().isoformat(),
            "source_pcap": args.input,
            "summary": {
                "total_dns_packets": 0,
                "security_hints": []
            },
            "suspicious": [],
            "flows": []
        }
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(json.dumps(result, indent=2))
        print(json.dumps({"status": "ok", "total_dns_packets": 0}))
        return

    print("[*] Matching queries với responses...", file=sys.stderr)
    flows = match_queries_responses(packets)
    print(f"[*] {len(flows)} DNS flows matched", file=sys.stderr)

    print("[*] Detecting suspicious domains...", file=sys.stderr)
    suspicious = detect_suspicious(flows)
    print(
        f"[*] {len(suspicious)} suspicious domains found",
        file=sys.stderr
    )

    summary = compute_summary(packets, flows, suspicious)

    result = {
        "timestamp":   datetime.utcnow().isoformat(),
        "source_pcap": args.input,
        "summary":     summary,
        "suspicious":  suspicious,
        "flows":       flows,
    }

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(result, indent=2))

    # Stdout cho agent
    print(json.dumps({
        "status":            "ok",
        "total_dns_packets": len(packets),
        "total_flows":       len(flows),
        "unique_domains":    summary["unique_domains"],
        "suspicious_count":  len(suspicious),
        "security_hints":    len(summary["security_hints"]),
        "output":            args.output,
    }, indent=2))

    print(
        f"[*] Saved → {args.output}",
        file=sys.stderr
    )

    # In suspicious domains ra stderr
    if suspicious:
        print("\n[!] Suspicious domains:", file=sys.stderr)
        for s in suspicious[:10]:
            print(
                f"    [{s['severity'].upper()}] {s['domain']} "
                f"(count={s['query_count']}) — "
                f"{'; '.join(s['reasons'][:2])}",
                file=sys.stderr
            )


if __name__ == "__main__":
    main()