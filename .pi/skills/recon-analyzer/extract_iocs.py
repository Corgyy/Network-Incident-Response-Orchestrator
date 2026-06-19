import json
import os
import ipaddress
import argparse
import math
import re
from collections import Counter

def is_public_ip(ip_str):
    if not ip_str or not isinstance(ip_str, str): return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_reserved)
    except ValueError: return False

def is_valid_hash(hash_str):
    if not hash_str or not isinstance(hash_str, str): return False
    h = hash_str.strip()
    return len(h) == 32 and h not in ["-", ""] and not all(c == '0' for c in h)

def calculate_entropy(text):
    if not text: return 0
    text_len = len(text)
    frequencies = Counter(text)
    return round(-sum((count / text_len) * math.log2(count / text_len) for count in frequencies.values()), 4)

def get_rarity_score(value, counter):
    if not value or not counter: return 100.0
    total = sum(counter.values())
    count = counter.get(value, 0)
    return round((1.0 - (count / total)) * 100, 1) if total > 0 else 100.0

def extract_from_text(text, victim_ip, attacker_ip):
    """Trích xuất động IP và Domain từ văn bản thô bằng Regex."""
    found = {"ip": [], "domain": []}
    if not text or not isinstance(text, str): return found
    
    # Regex cho IPv4
    ip_pattern = r'\b\d{1,3}(?:\.\d{1,3}){3}\b'
    # Regex cho Domain (với kiểm tra sơ bộ độ dài TLD)
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b'
    
    # Tìm IP
    ips = re.findall(ip_pattern, text)
    for ip in ips:
        if ip not in [victim_ip, attacker_ip]:
            found["ip"].append(ip)
            
    # Tìm Domain
    domains = re.findall(domain_pattern, text)
    # Các phần mở rộng phổ biến cần loại bỏ (Nhiễu)
    noise_exts = {'.exe', '.dll', '.sys', '.lnk', '.tmp', '.ini', '.dat', '.php', '.jpg', '.jpeg', '.png', '.gif'}
    for dom in domains:
        dom_low = dom.lower()
        # Loại bỏ nếu là IP hoặc có phần mở rộng là file
        if not any(dom_low.endswith(ext) for ext in noise_exts) and not re.match(ip_pattern, dom):
            if dom_low not in ["microsoft.com", "google.com", "windows.com", "localhost"]:
                found["domain"].append(dom)
                
    return found

def extract_iocs(log_file, network_file, triage_file, recon_file, output_file):
    pools = {"ip": {}, "hash": {}, "domain": {}}
    
    # 0. Contexts
    attacker_ip = None
    victim_ip = None
    if os.path.exists(triage_file):
        try:
            with open(triage_file, 'r') as f:
                d = json.load(f)
                ents = d.get("inferred_entities", {})
                victim_ip = ents.get("victim_ip")
                attacker_ip = ents.get("attacker_ip")
                for v in ents.values():
                    v_str = str(v).lower()
                    if is_public_ip(v_str):
                        pools["ip"][v_str] = {"score": 10000, "contexts": {"Primary Triage Entity"}, "sources": {"triage"}, "orig": v_str}
        except Exception: pass

    # Stats for rarity
    path_stats = Counter()
    rel_stats = Counter()
    host_data = {}
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r') as f:
                host_data = json.load(f)
                for proc in host_data.get("suspicious_processes", []):
                    img = proc.get("image", "").lower()
                    p_img = proc.get("parent_image", "").lower()
                    if img: path_stats[os.path.dirname(img)] += 1
                    if img and p_img: rel_stats[f"{p_img}->{img}"] += 1
        except Exception: pass

    def add_ioc(itype, val, score, context, src, entity_name=None):
        if not val: return
        val_low = str(val).lower()
        pool = pools[itype]
        
        # Deduplication logic for Hashes
        if itype == "hash" and entity_name:
            for existing_val, d in pool.items():
                if d.get("entity") == entity_name.lower():
                    if score > d["score"]:
                        del pool[existing_val]
                        break
                    else: return
        
        if val_low not in pool:
            pool[val_low] = {"score": 0, "contexts": set(), "sources": set(), "orig": val, "entity": entity_name.lower() if entity_name else None}
        
        pool[val_low]["score"] += score
        pool[val_low]["contexts"].add(context)
        pool[val_low]["sources"].add(src)

    # 1. Host Analysis (The Core of Zero-Hardcode)
    if host_data:
        for proc in host_data.get("suspicious_processes", []):
            img = proc.get("image", "")
            cmd = proc.get("command_line", "")
            p_img = proc.get("parent_image", "")
            
            # Metrics for scoring
            p_rarity = get_rarity_score(os.path.dirname(img).lower(), path_stats)
            r_rarity = get_rarity_score(f"{p_img}->{img}".lower(), rel_stats)
            
            # 1.1 Hash Extraction (MD5 Preferred)
            md5 = (proc.get("hashes") or {}).get("MD5")
            if md5 and is_valid_hash(md5):
                add_ioc("hash", md5, 100 + p_rarity + r_rarity, f"Execution: {os.path.basename(img)}", "host_proc", entity_name=os.path.basename(img))
            
            # 1.2 Dynamic Extraction from Command Line (REGEX)
            dynamic = extract_from_text(cmd, victim_ip, attacker_ip)
            for ip in dynamic["ip"]:
                is_pub = is_public_ip(ip)
                score = 150 if is_pub else 50
                add_ioc("ip", ip, score, f"Found in command of {os.path.basename(img)}", "host_cmd_regex")
            
            for dom in dynamic["domain"]:
                ent = calculate_entropy(dom)
                # High entropy + being in a suspicious command = high score
                add_ioc("domain", dom, 150 + (ent * 40), f"Found in command of {os.path.basename(img)}", "host_cmd_regex")

        # 1.3 Direct IP extraction from log results
        for ip in host_data.get("unique_external_ips", []):
            is_pub = is_public_ip(ip)
            if ip != victim_ip and ip != attacker_ip:
                score = 200 if is_pub else 30
                add_ioc("ip", ip, score, "External IP from host logs", "host_log_ip")

    # 2. Network Analysis
    if os.path.exists(network_file):
        try:
            with open(network_file, 'r') as f:
                net_data = json.load(f)
                for ip in net_data.get("distinct_dest_ips", []):
                    is_pub = is_public_ip(ip)
                    if ip != victim_ip and ip != attacker_ip:
                        score = 150 if is_pub else 20
                        add_ioc("ip", ip, score, "Network stream target", "net_stream")
                
                # DNS extraction
                for domain in net_data.get("extracted_artifacts", {}).get("dns_queries", []):
                    clean = domain.strip().lower().rstrip('.')
                    if clean and "." in clean and not is_public_ip(clean):
                        ent = calculate_entropy(clean.split('.')[0])
                        add_ioc("domain", clean, 100 + (ent * 50), f"DNS Query (Entropy: {ent})", "net_dns")
        except Exception: pass

    # 3. Recon Enrichment
    if os.path.exists(recon_file):
        try:
            with open(recon_file, 'r') as f:
                r_data = json.load(f)
                dom = r_data.get("sources", {}).get("abuseipdb", {}).get("domain")
                if dom and "." in dom and dom not in ["microsoft.com", "google.com"]:
                    add_ioc("domain", dom, 500, "Associated domain from OSINT", "recon_enrich")
        except Exception: pass

    # 4. Balanced Export 5:5:5
    final_iocs = []
    for itype in ["ip", "hash", "domain"]:
        # Sort by score and count of sources
        sl = sorted(pools[itype].values(), key=lambda x: x["score"] + (1000 if len(x["sources"]) > 1 else 0), reverse=True)
        for item in sl[:5]:
            final_iocs.append({
                "type": itype, 
                "value": item["orig"], 
                "score": round(item["score"], 1),
                "context": " | ".join(list(item["contexts"])[:2]), 
                "sources": list(item["sources"])
            })

    output_data = {
        "metadata": {"engine": "Zero-Hardcode V2.0", "author": "Orchestrator"}, 
        "iocs": final_iocs,
        "commands": [f"python3 ./.pi/skills/recon-analyzer/analyze_recon.py --ioc {i['value']} --output ./reports/recon_pivot_{i['type']}_{i['value'].replace(':','_').replace('/','_')}.json" for i in final_iocs]
    }
    
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f: 
        json.dump(output_data, f, indent=4)
    print(f"[+] Zero-Hardcode Extraction complete. Saved -> {output_file}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--log-file", default="./reports/log_collector_result.json")
    p.add_argument("--net-file", default="./reports/network_analyzer_result.json")
    p.add_argument("--triage-file", default="./reports/triage_context.json")
    p.add_argument("--recon-file", default="./reports/recon_result.json")
    p.add_argument("--output", default="./reports/pivot_manifest.json")
    args = p.parse_args()
    extract_iocs(args.log_file, args.net_file, args.triage_file, args.recon_file, args.output)
