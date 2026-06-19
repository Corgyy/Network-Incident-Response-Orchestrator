import json
import os
import ipaddress
import argparse
import math
import re
from collections import Counter
from datetime import datetime, timezone

class CorrelationEngine:
    def __init__(self, victim_ip, attacker_ip):
        self.victim_ip = victim_ip
        self.attacker_ip = attacker_ip
        self.pools = {"ip": {}, "hash": {}, "domain": {}}
        # Common file extensions that look like domains but are noise
        self.noise_exts = {'.exe', '.dll', '.sys', '.lnk', '.tmp', '.ini', '.dat', '.php', '.jpg', '.jpeg', '.png', '.gif'}
        self.ip_pattern = r'\b\d{1,3}(?:\.\d{1,3}){3}\b'
        self.domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b'
        self.file_pattern = r'\b[a-zA-Z0-9_\-\.]+\.[a-zA-Z0-9]{2,4}\b'
        
        # Internal state for correlation
        self.host_net_conns = [] # EventID 3
        self.host_file_creations = [] # EventID 11
        self.network_anomalies = {"ip": set(), "port": set(), "domain": set()}
        
        # Frequency baseline trackers
        self.domain_frequency = Counter()
        self.total_domain_extractions = 0

    def parse_time(self, ts_str):
        if not ts_str: return None
        ts_str = str(ts_str).replace('Z', '+00:00')
        try:
            return datetime.fromisoformat(ts_str).astimezone(timezone.utc)
        except Exception:
            try:
                # Fallback for Splunk-style or other formats
                return datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
            except: return None

    def calculate_entropy(self, text):
        if not text: return 0
        text_len = len(text)
        frequencies = Counter(text)
        return round(-sum((count / text_len) * math.log2(count / text_len) for count in frequencies.values()), 4)

    def is_public_ip(self, ip_str):
        if not ip_str: return False
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_reserved)
        except ValueError: return False

    def add_ioc(self, itype, val, score, context, source):
        if not val: return
        val_low = str(val).lower()
        if val_low not in self.pools[itype]:
            self.pools[itype][val_low] = {
                "score": 0, 
                "contexts": set(), 
                "sources": set(), 
                "orig": val,
                "correlation_confirmed": False
            }
        
        entry = self.pools[itype][val_low]
        entry["score"] += score
        entry["contexts"].add(context)
        entry["sources"].add(source)

    def extract_from_text(self, text):
        found = {"ip": [], "domain": [], "file": []}
        if not text or not isinstance(text, str): return found
        
        # IP Extraction
        ips = re.findall(self.ip_pattern, text)
        for ip in ips:
            if ip not in [self.victim_ip, self.attacker_ip]:
                found["ip"].append(ip)
        
        # Domain Extraction (Improved)
        domains = re.findall(self.domain_pattern, text)
        for dom in domains:
            dom_low = dom.lower()
            # Strict filtering: must not be a known noise domain or file fragment
            if any(dom_low.endswith(ext) for ext in self.noise_exts): continue
            
            # Avoid matching parts of Windows paths
            if "\\" in text and dom in text.split("\\"): continue
            
            if not re.match(self.ip_pattern, dom):
                # Always exclude localhost as a generic baseline
                if dom_low != "localhost":
                    found["domain"].append(dom)
                    # Track frequency for algorithmic baseline filtering
                    self.domain_frequency[dom_low] += 1
                    self.total_domain_extractions += 1
        
        # File Extraction
        files = re.findall(self.file_pattern, text)
        for f in files:
            if any(f.lower().endswith(ext) for ext in ['.exe', '.dll', '.tmp', '.bat', '.ps1', '.vbs', '.cmd']):
                found["file"].append(f)
        return found

    def process_host_logs(self, host_data):
        if not host_data: return
        
        # First Pass: Extract and build frequency baselines
        temp_extracted_data = []
        for proc in host_data.get("suspicious_processes", []):
            img = proc.get("image", "")
            cmd = proc.get("command_line", "")
            decoded = proc.get("decoded_command", "")
            img_name = os.path.basename(img)
            
            # Hash extraction
            hashes = proc.get("hashes") or {}
            for h_type, h_val in hashes.items():
                self.add_ioc("hash", h_val, 200, f"Executed via {img_name}", f"host_log_{h_type}")
            
            # Extract IPs and domains for baseline profiling
            current_extractions = []
            for text_source, src_tag in [(cmd, "host_cmd"), (decoded, "host_decoded")]:
                if not text_source: continue
                dynamic = self.extract_from_text(text_source)
                current_extractions.append({
                    "dynamic": dynamic, "src_tag": src_tag
                })
            
            temp_extracted_data.append({
                "img_name": img_name, "extractions": current_extractions
            })
        
        # Algorithmic Threshold: If a domain appears in more than 5% of all extractions, it's environmental noise.
        noise_threshold = 0.05
        environmental_noise = set()
        if self.total_domain_extractions > 10:
            for dom, count in self.domain_frequency.items():
                if (count / self.total_domain_extractions) > noise_threshold:
                    environmental_noise.add(dom)

        # Second Pass: Score items, applying the algorithmic baseline filter
        for item in temp_extracted_data:
            img_name = item["img_name"]
            for ext in item["extractions"]:
                dynamic = ext["dynamic"]
                src_tag = ext["src_tag"]
                
                for ip in dynamic["ip"]:
                    self.add_ioc("ip", ip, 150, f"Found in {src_tag} of {img_name}", f"{src_tag}_regex")
                for dom in dynamic["domain"]:
                    if dom.lower() in environmental_noise: continue # Algorithmic whitelist
                    ent = self.calculate_entropy(dom)
                    self.add_ioc("domain", dom, 150 + (ent * 40), f"Found in {src_tag} of {img_name} (Entropy: {ent})", f"{src_tag}_regex")

        # 2. Store Network Connections (EventID 3)
        self.host_net_conns = host_data.get("network_connections", [])
        for conn in self.host_net_conns:
            ip = conn.get("destination_ip")
            if ip and ip not in [self.victim_ip, self.attacker_ip]:
                is_pub = self.is_public_ip(ip)
                score = 100 if is_pub else 30
                ctx = f"Host process {os.path.basename(conn.get('image',''))} connected to {ip}"
                self.add_ioc("ip", ip, score, ctx, "host_event_id_3")

        # 3. Store File Creations (EventID 11)
        self.host_file_creations = host_data.get("file_creation_events", [])
        for fce in self.host_file_creations:
            fname = os.path.basename(fce.get("target_filename", ""))
            if fname:
                self.add_ioc("domain", fname, 50, f"File created by {os.path.basename(fce.get('image',''))}", "host_event_id_11")

    def process_network_data(self, net_data):
        if not net_data: return
        
        # 1. Critical & Contextual Findings
        for finding in net_data.get("critical_findings", []) + net_data.get("contextual_findings", []):
            f_type = finding.get("type")
            val = finding.get("value")
            score = finding.get("score", 0)
            ctx = finding.get("context", "")
            
            if "ip" in f_type.lower() or ":" in val:
                ip = val.split(':')[0] if ":" in val else val
                if self.is_public_ip(ip):
                    self.network_anomalies["ip"].add(ip)
                    self.add_ioc("ip", ip, score, ctx, "net_anomaly")
            
            if "domain" in f_type.lower() or "url" in f_type.lower() or "uri" in f_type.lower():
                self.network_anomalies["domain"].add(val)
                self.add_ioc("domain", val, score, ctx, "net_anomaly")
            
            if "port" in f_type.lower():
                port_match = re.search(r':(\d+)', val)
                if port_match: self.network_anomalies["port"].add(port_match.group(1))

    def apply_cross_correlation(self):
        """ALGORITHMIC CORRELATION RULES"""
        
        # 1. Time-Based Process-Network Correlation (EventID 3 Match with Network Anomaly)
        for conn in self.host_net_conns:
            dest_ip = conn.get("destination_ip")
            dest_port = str(conn.get("destination_port"))
            proc_name = os.path.basename(conn.get("image", ""))
            
            # Match with dynamically identified network anomalies
            if dest_ip in self.network_anomalies["ip"] or dest_port in self.network_anomalies["port"]:
                # Exclude broadcast/multicast from critical boost
                if dest_ip.endswith(".255") or dest_ip.startswith("224."): continue

                if dest_ip in self.pools["ip"]:
                    data = self.pools["ip"][dest_ip.lower()]
                    data["score"] += 5000
                    data["correlation_confirmed"] = True
                    data["contexts"].add(f"MATCH: {proc_name} -> {dest_ip}:{dest_port} (Anomalous Flow)")

        # 2. Command-File Creation Linkage (Simplified implementation)
        # This identifies droppers by matching strings in command lines with files created shortly after.
        created_files = {os.path.basename(f.get("target_filename", "")).lower() for f in self.host_file_creations}
        for val_low, data in self.pools["domain"].items():
            if val_low in created_files and "host_cmd_regex" in data["sources"]:
                data["score"] += 3000
                data["correlation_confirmed"] = True
                data["contexts"].add(f"MATCH: Command-referenced file '{val_low}' was created on disk")

        # 3. Decoded Payload Match
        for val_low, data in self.pools["ip"].items():
            if "host_decoded_regex" in data["sources"] and ("net_anomaly" in data["sources"] or "host_event_id_3" in data["sources"]):
                data["score"] += 8000
                data["correlation_confirmed"] = True
                data["contexts"].add("MATCH: IOC in Decoded Payload + Network Activity")

    def get_manifest(self):
        final_iocs = []
        recon_commands = []
        MAX_RECON_PER_TYPE = 4
        MAX_TOTAL_RECON = 12
        
        # Categorized targets for smart selection
        categorized_targets = {"ip": [], "hash": [], "domain": []}

        for itype in ["ip", "hash", "domain"]:
            for val_low in self.pools[itype]:
                data = self.pools[itype][val_low]
                unique_contexts = []
                seen_base_ctx = set()
                # Prioritize MATCH: contexts
                sorted_raw_contexts = sorted(list(data["contexts"]), key=lambda x: not x.startswith("MATCH:"))
                for ctx in sorted_raw_contexts:
                    base = ctx.split(' (')[0].split(' linked to')[0].split(' Found in')[0]
                    if base not in seen_base_ctx:
                        unique_contexts.append(ctx)
                        seen_base_ctx.add(base)
                data["unique_contexts"] = unique_contexts[:3]

            sorted_items = sorted(self.pools[itype].values(), key=lambda x: (x["correlation_confirmed"], x["score"]), reverse=True)
            
            # Step 1: Dynamic Thresholding for Manifest
            for item in sorted_items:
                # Include ONLY if confirmed OR score is significantly high (e.g., >= 150)
                if not (item["correlation_confirmed"] or item["score"] >= 150):
                    continue
                    
                final_iocs.append({
                    "type": itype,
                    "value": item["orig"],
                    "score": round(min(item["score"], 10000), 1),
                    "context": " | ".join(item["unique_contexts"]),
                    "sources": list(item["sources"]),
                    "confirmed": item["correlation_confirmed"]
                })
                
                # Step 2: Smart Selection for Recon Agent
                if len(categorized_targets[itype]) < MAX_RECON_PER_TYPE:
                    val = item["orig"]
                    if itype == "ip":
                        # Never recon internal/private IPs
                        if not self.is_public_ip(val) or val.endswith(".255"):
                            continue
                    categorized_targets[itype].append({
                        "type": itype,
                        "value": val,
                        "confirmed": item["correlation_confirmed"]
                    })

        # Step 3: Final Command Compilation (Priority first)
        all_targets = []
        # First add all confirmed targets
        for itype in categorized_targets:
            confirmed = [t for t in categorized_targets[itype] if t["confirmed"]]
            all_targets.extend(confirmed)
            categorized_targets[itype] = [t for t in categorized_targets[itype] if not t["confirmed"]]
        
        # Then fill remaining budget with top scored non-confirmed targets
        for itype in categorized_targets:
            all_targets.extend(categorized_targets[itype])
        
        # Build commands up to MAX_TOTAL_RECON
        for target in all_targets[:MAX_TOTAL_RECON]:
            cmd = f"python3 ./.pi/skills/recon-analyzer/analyze_recon.py --ioc {target['value']} --output ./reports/recon_pivot_{target['type']}_{target['value'].replace(':','_').replace('/','_')}.json"
            recon_commands.append(cmd)
        
        return {
            "metadata": {
                "engine": "Algorithmic Correlation Engine V2.3",
                "status": "Dynamic Threshold Mode",
                "timestamp": str(datetime.now(timezone.utc)),
                "manifest_count": len(final_iocs),
                "recon_command_count": len(recon_commands)
            },
            "iocs": final_iocs,
            "commands": recon_commands
        }

def main():
    parser = argparse.ArgumentParser(description="Correlate Host and Network Evidence (Algorithmic)")
    parser.add_argument("--log-file", required=True)
    parser.add_argument("--net-file", required=True)
    parser.add_argument("--triage-file", required=True)
    parser.add_argument("--output", default="./reports/pivot_manifest.json")
    args = parser.parse_args()

    victim_ip, attacker_ip = None, None
    if os.path.exists(args.triage_file):
        try:
            with open(args.triage_file, 'r') as f:
                triage = json.load(f).get("inferred_entities", {})
                victim_ip = triage.get("victim_ip")
                attacker_ip = triage.get("attacker_ip")
        except Exception: pass

    engine = CorrelationEngine(victim_ip, attacker_ip)

    if os.path.exists(args.log_file):
        try:
            with open(args.log_file, 'r') as f: 
                engine.process_host_logs(json.load(f))
        except Exception: pass
    
    if os.path.exists(args.net_file):
        try:
            with open(args.net_file, 'r') as f: 
                engine.process_network_data(json.load(f))
        except Exception: pass

    engine.apply_cross_correlation()

    manifest = engine.get_manifest()
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=4)
    print(f"[+] Algorithmic correlation complete. Manifest saved to {args.output}")

if __name__ == "__main__":
    main()
