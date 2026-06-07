import asyncio
import httpx
import json
import argparse
import os
import sys
from dotenv import load_dotenv

# Tự động tìm và nạp các biến trong file .env vào hệ thống
load_dotenv() 

class ReconAgent:
    def __init__(self, vt_key=None, abuse_key=None):
        # Kiểm tra và ưu tiên lấy Key từ biến môi trường .env nếu CLI truyền vào chuỗi mặc định
        self.vt_api_key = vt_key if vt_key and vt_key != "YOUR_VIRUSTOTAL_KEY" else os.getenv("VIRUSTOTAL_API_KEY")
        self.abuse_api_key = abuse_key if abuse_key and abuse_key != "YOUR_ABUSEIPDB_KEY" else os.getenv("ABUSEIPDB_API_KEY")
        self.headers = {"Accept": "application/json"}

    async def check_abuse_ipdb(self, client: httpx.AsyncClient, ip: str) -> dict:
        if not self.abuse_api_key or self.abuse_api_key in ["YOUR_ABUSEIPDB_KEY", ""]:
            print("[-] Không tìm thấy AbuseIPDB API Key hợp lệ.")
            return {"abuse_score": 0, "country_code": "Unknown"}
            
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {**self.headers, "Key": self.abuse_api_key}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        try:
            response = await client.get(url, headers=headers, params=params, timeout=5.0)
            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "country_code": data.get("countryCode", "Unknown")
                }
        except Exception as e:
            print(f"[-] Lỗi AbuseIPDB API: {e}")
        return {"abuse_score": 0, "country_code": "Unknown"}

    async def check_virus_total(self, client: httpx.AsyncClient, ip: str) -> dict:
        if not self.vt_api_key or self.vt_api_key in ["YOUR_VIRUSTOTAL_KEY", ""]:
            print("[-] Không tìm thấy VirusTotal API Key hợp lệ.")
            return {"malicious_count": 0}
            
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {**self.headers, "x-apikey": self.vt_api_key}
        try:
            response = await client.get(url, headers=headers, timeout=5.0)
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {"malicious_count": stats.get("malicious", 0)}
        except Exception as e:
            print(f"[-] Lỗi VirusTotal API: {e}")
        return {"malicious_count": 0}

    async def run(self, src_ip: str, output_path: str):
        print(f"[*] Đang bắt đầu trinh sát IP: {src_ip}...")
        
        # XỬ LÝ THỰC TẾ: Nếu là IP nội bộ, xuất kết quả an toàn luôn, không cần gọi API ngoài Internet
        if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("127."):
            print("[!] Phát hiện IP nội bộ/vòng lặp. Mặc định an toàn.")
            recon_output = {
                "agent_name": "Recon_OSINT_Agent",
                "target_ip": src_ip,
                "reputation_score": 0,
                "country_code": "Internal Network",
                "malicious_engines": 0,
                "is_malicious": False
            }
        else:
            # IP Public ngoài Internet thực tế -> Tiến hành trinh sát tình báo
            try:
                async with httpx.AsyncClient(verify=False) as client:
                    task_abuse = self.check_abuse_ipdb(client, src_ip)
                    task_vt = self.check_virus_total(client, src_ip)
                    abuse_res, vt_res = await asyncio.gather(task_abuse, task_vt)
                    
                is_malicious = abuse_res["abuse_score"] > 25 or vt_res["malicious_count"] > 0
                
                recon_output = {
                    "agent_name": "Recon_OSINT_Agent",
                    "target_ip": src_ip,
                    "reputation_score": abuse_res["abuse_score"],
                    "country_code": abuse_res["country_code"],
                    "malicious_engines": vt_res["malicious_count"],
                    "is_malicious": is_malicious
                }
            except Exception as e:
                print(f"[-] Thất bại khi kết nối API OSINT: {e}")
                return

        # Ép tạo thư mục và ghi file JSON đầu ra
        abs_output_path = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_output_path), exist_ok=True)
        
        with open(abs_output_path, "w", encoding="utf-8") as f:
            json.dump(recon_output, f, indent=4, ensure_ascii=False)
        print(f"[+] Ghi file THÀNH CÔNG tại: {abs_output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reconnaissance Agent CLI")
    parser.add_argument("--ip", required=True, help="Địa chỉ IP cần trinh sát")
    parser.add_argument("--output", required=True, help="Đường dẫn file JSON đầu ra")
    
    parser.add_argument("--vt_key", default="YOUR_VIRUSTOTAL_KEY", help="VirusTotal API Key")
    parser.add_argument("--abuse_key", default="YOUR_ABUSEIPDB_KEY", help="AbuseIPDB API Key")
    
    args = parser.parse_args()
    
    agent = ReconAgent(vt_key=args.vt_key, abuse_key=args.abuse_key)
    try:
        asyncio.run(agent.run(args.ip, args.output))
    except Exception as main_e:
        print(f"[-] Lỗi khởi chạy Asyncio: {main_e}")