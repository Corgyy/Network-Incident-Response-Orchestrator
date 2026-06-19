import json
import argparse
import os
import sys
import re
import urllib.request
import urllib.parse

def load_env_file(file_path=".env"):
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"): continue
                    if "=" in line:
                        key, value = line.split("=", 1)
                        os.environ[key.strip()] = value.strip().strip("'").strip('"')
            return True
        except Exception: pass
    return False

load_env_file()

class ReconAgent:
    def __init__(self, vt_key=None, abuseip_key=None, threatfox_key=None):
        self.vt_api_key = vt_key or os.getenv("VT_API_KEY")
        self.abuseip_api_key = abuseip_key or os.getenv("ABUSEIPDB_API_KEY")
        self.threatfox_api_key = threatfox_key or os.getenv("THREATFOX_API_KEY")

    def detect_ioc_type(self, ioc: str) -> str:
        if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ioc): return "ip"
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc): return "hash"
        if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", ioc): return "domain"
        return "unknown"

    def _http_request(self, url, headers=None, data=None, method="GET"):
        try:
            if data and isinstance(data, dict):
                data = json.dumps(data).encode('utf-8')
            
            req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
            with urllib.request.urlopen(req, timeout=15) as response:
                return response.status, json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            try: body = json.loads(e.read().decode('utf-8'))
            except: body = None
            return e.code, body
        except Exception as e:
            return 0, str(e)

    def check_virus_total(self, ioc: str, ioc_type: str) -> dict:
        if not self.vt_api_key: return {"status": "missing_api_key"}
        
        map = {"ip": f"ip_addresses/{ioc}", "domain": f"domains/{ioc}", "hash": f"files/{ioc}"}
        if ioc_type not in map: return {"status": "unsupported"}

        url = f"https://www.virustotal.com/api/v3/{map[ioc_type]}"
        headers = {"x-apikey": self.vt_api_key, "Accept": "application/json"}
        code, data = self._http_request(url, headers)
        
        if code == 200:
            attr = data.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            return {"malicious_count": stats.get("malicious", 0), "reputation": attr.get("reputation", 0), "status": "success"}
        return {"status": f"error_{code}", "message": str(data)}

    def check_abuseipdb(self, ip: str) -> dict:
        if not self.abuseip_api_key: return {"status": "missing_api_key"}
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {"Key": self.abuseip_api_key, "Accept": "application/json"}
        code, data = self._http_request(url, headers)
        if code == 200:
            d = data.get("data", {})
            return {"abuse_score": d.get("abuseConfidenceScore", 0), "total_reports": d.get("totalReports", 0), "status": "success"}
        return {"status": f"error_{code}", "message": str(data)}

    def check_threatfox(self, ioc: str, ioc_type: str) -> dict:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        payload = {"query": "search_ioc", "search_term": ioc}
        headers = {"Content-Type": "application/json"}
        if self.threatfox_api_key: headers["Auth-Key"] = self.threatfox_api_key
        
        code, data = self._http_request(url, headers, data=payload, method="POST")
        if code == 200:
            status = data.get("query_status")
            if status == "ok":
                res = data.get("data", [])
                return {"malicious_count": len(res), "malware": res[0].get("malware_printable") if res else "N/A", "status": "success"}
            elif status == "no_result":
                return {"malicious_count": 0, "status": "success", "info": "No results found"}
            return {"status": f"api_{status}", "message": str(data)}
        return {"status": f"error_{code}", "message": str(data)}

    def run(self, ioc: str, output_path: str):
        ioc_type = self.detect_ioc_type(ioc)
        res = {"ioc": ioc, "type": ioc_type, "sources": {}}
        
        res["sources"]["virustotal"] = self.check_virus_total(ioc, ioc_type)
        if ioc_type == "ip": res["sources"]["abuseipdb"] = self.check_abuseipdb(ioc)
        res["sources"]["threatfox"] = self.check_threatfox(ioc, ioc_type)
        
        # Aggregation logic
        is_m = False
        if res["sources"]["virustotal"].get("malicious_count", 0) > 0: is_m = True
        if ioc_type == "ip" and res["sources"].get("abuseipdb", {}).get("abuse_score", 0) > 50: is_m = True
        if res["sources"]["threatfox"].get("malicious_count", 0) > 0: is_m = True
        res["is_malicious"] = is_m

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=4)
        print(f"[+] Recon complete for {ioc} -> {output_path}")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--ioc", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--vt_key")
    p.add_argument("--abuseip_key")
    p.add_argument("--threatfox_key")
    args = p.parse_args()
    ReconAgent(args.vt_key, args.abuseip_key, args.threatfox_key).run(args.ioc, args.output)
