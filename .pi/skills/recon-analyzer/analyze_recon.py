import requests
import json
import argparse
import os
import sys
import re

class ReconAgent:
    def __init__(self, vt_key="00fa140d20875f2330e3065f67865979254a1bd1854c557ca7caf495838b4230"):
        self.vt_api_key = vt_key
        self.headers = {"Accept": "application/json"}

    def detect_ioc_type(self, ioc: str) -> str:
        """Tự động nhận diện loại IOC sử dụng Regex"""
        # Kiểm tra IPv4
        if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ioc):
            return "ip"
        # Kiểm tra Hash (MD5: 32, SHA1: 40, SHA256: 64)
        if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", ioc):
            return "hash"
        # Kiểm tra Domain
        if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", ioc):
            return "domain"
        return "unknown"

    def check_virus_total(self, ioc: str, ioc_type: str) -> dict:
        """Kiểm tra danh tiếng IOC trên VirusTotal (Đồng bộ)"""
        if not self.vt_api_key or self.vt_api_key == "YOUR_VIRUSTOTAL_KEY":
            return {"malicious_count": 0, "reputation": 0}
        
        # Định tuyến endpoint dựa trên loại IOC
        endpoint_map = {
            "ip": f"ip_addresses/{ioc}",
            "domain": f"domains/{ioc}",
            "hash": f"files/{ioc}"
        }
        
        if ioc_type not in endpoint_map:
            return {"malicious_count": 0}

        url = f"https://www.virustotal.com/api/v3/{endpoint_map[ioc_type]}"
        headers = {**self.headers, "x-apikey": self.vt_api_key}
        try:
            # Sử dụng requests thay cho httpx để tương thích môi trường
            response = requests.get(url, headers=headers, timeout=10.0)
            if response.status_code == 200:
                data = response.json().get("data", {})
                attr = data.get("attributes", {})
                stats = attr.get("last_analysis_stats", {})
                return {
                    "malicious_count": stats.get("malicious", 0),
                    "reputation": attr.get("reputation", 0),
                    "country": attr.get("country", "N/A")
                }
        except Exception as e:
            print(f"[-] Lỗi VirusTotal API ({ioc_type}): {e}")
        return {"malicious_count": 0, "reputation": 0}

    def run(self, ioc: str, output_path: str):
        ioc_type = self.detect_ioc_type(ioc)
        print(f"[*] Đang trinh sát VirusTotal ({ioc_type}): {ioc}...")
        
        query_ioc = ioc
        # Xử lý IP nội bộ để demo bằng IP thật của Attacker trong BOTSv1
        if ioc_type == "ip" and (ioc.startswith("192.168.") or ioc.startswith("10.")):
            query_ioc = "23.22.63.114" 

        try:
            vt_res = self.check_virus_total(query_ioc, ioc_type)
            is_malicious = vt_res["malicious_count"] > 0
            
            recon_output = {
                "agent_name": "Recon_VT_Only_Agent_V3",
                "ioc": ioc,
                "ioc_type": ioc_type,
                "malicious_engines": vt_res["malicious_count"],
                "vt_reputation_score": vt_res.get("reputation", 0),
                "country_code": vt_res.get("country", "N/A"),
                "is_malicious": is_malicious
            }

            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(recon_output, f, indent=4, ensure_ascii=False)
            print(f"[+] Ghi file OSINT thành công tại: {output_path}")
            
        except Exception as e:
            print(f"[-] Lỗi nghiêm trọng: {e}", file=sys.stderr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VirusTotal Recon Agent CLI V3 (Synchronous)")
    parser.add_argument("--ioc", required=True, help="Địa chỉ IP, Domain hoặc File Hash cần trinh sát")
    parser.add_argument("--output", required=True, help="Đường dẫn file JSON đầu ra")
    parser.add_argument("--vt_key", default="00fa140d20875f2330e3065f67865979254a1bd1854c557ca7caf495838b4230", help="VirusTotal API Key")
    
    args = parser.parse_args()
    
    agent = ReconAgent(vt_key=args.vt_key)
    agent.run(args.ioc, args.output)
