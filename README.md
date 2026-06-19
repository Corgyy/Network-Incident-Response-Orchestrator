# Network Incident Response Orchestrator

`Network Incident Response Orchestrator` là đồ án tự động hóa quy trình `Incident Response` theo mô hình `Multi-Agent`. Hệ thống nhận một IOC đầu vào, điều phối các agent chuyên biệt để phân tích cảnh báo, log máy chủ, lưu lượng mạng, làm giàu OSINT, liên kết bằng chứng và sinh báo cáo sự cố.

## Mục tiêu

- Tự động hóa quy trình điều tra sự cố an ninh mạng.
- Giảm tải phân tích thủ công trong môi trường SOC.
- Liên kết bằng chứng từ host log và network log.
- Hỗ trợ lập báo cáo theo MITRE ATT&CK và Cyber Kill Chain.

## Kiến trúc

Hệ thống gồm một `Orchestrator Agent` và các sub-agent:

- `alert-triage-agent`
- `recon-agent`
- `log-collector-agent`
- `network-agent`
- `correlation-agent`
- `reporting-agent`

Các tác vụ chính được thực thi bằng Python scripts trong `./.pi/skills/`.

## Luồng hoạt động

### 1. Triage

- Script: `./.pi/skills/alert-triage/triage_alerts.py`
- Xác định `attacker_ip`, `victim_ip`, timeline và time window điều tra.

### 2. Initial Recon

- Script: `./.pi/skills/recon-analyzer/analyze_recon.py`
- Truy vấn OSINT cho `IP`, `domain`, `MD5`, `SHA256`.
- Nguồn dùng: `VirusTotal`, `AbuseIPDB`, `ThreatFox`.

### 3. Deep Evidence Collection

Chạy song song 2 nhánh:

- Host analysis: `./.pi/skills/log-collector/collect_logs.py`
- Network analysis: `./.pi/skills/network-analyzer/analyze_network.py`

Host analysis tập trung vào:
- Process creation
- Network connection
- File creation
- Registry persistence
- WMI persistence

Network analysis tập trung vào:
- HTTP URI
- DNS query
- Destination IP
- Port distribution
- Flow volume
- Beaconing và anomaly detection

### 4. Correlation

- Script: `./.pi/skills/correlation-analyzer/correlation_analyzer.py`
- Liên kết bằng chứng giữa host và network.
- Xác định IOC có độ tin cậy cao để pivot tiếp.

### 5. Pivot Recon

- Mở rộng điều tra với các IOC mới như `IP`, `domain`, `hash`.
- Truy vấn song song để tăng tốc độ điều tra.

### 6. Reporting

- Tổng hợp kết quả điều tra.
- Ánh xạ MITRE ATT&CK.
- Xây dựng Cyber Kill Chain.
- Sinh báo cáo Incident Response cuối cùng.

## Cấu trúc thư mục

```text
.
├── .pi/
│   ├── agents/
│   ├── chains/
│   ├── prompts/
│   └── skills/
├── data/
├── reports/
├── config.json
└── README.md
```

## Cách chạy

Yêu cầu:

- Python `3.8+`
- Kết nối Internet để truy vấn OSINT
- Dữ liệu trong `./data/`

Ví dụ chạy điều tra qua orchestrator:

```bash
pi "Dựa trên .pi/AGENT.md, hãy điều tra 40.80.148.42 bằng cách điều phối các sub-agent, lưu báo cáo vào folder reports"
```

Có thể chạy từng phase bằng các script trong `./.pi/skills/` nếu cần kiểm thử riêng.

## Công nghệ và dữ liệu

- Python
- Multi-Agent Architecture
- Sysmon logs
- Network streams
- Splunk BOTSv1 dataset
- VirusTotal API
- AbuseIPDB API
- ThreatFox API

Thư mục `./data/` chứa dữ liệu thực nghiệm phục vụ điều tra, được lấy từ `Splunk Boss of the SOC v1 (BOTSv1)` challenge/dataset. Đây là bộ dữ liệu mô phỏng các kịch bản tấn công thực tế trong môi trường doanh nghiệp và cung cấp đồng thời log máy chủ cùng lưu lượng mạng, phù hợp để kiểm thử các bước triage, host forensics, network forensics và correlation của project.

## Hạn chế hiện tại

- Chưa hỗ trợ log thời gian thực.
- Chưa tích hợp trực tiếp với SIEM thực tế.
- Phụ thuộc vào nguồn OSINT bên ngoài cho phần enrichment.
