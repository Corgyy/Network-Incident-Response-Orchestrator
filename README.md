# Network Incident Response Orchestrator (Topic 09)

## Tổng quan
Hệ thống tự động điều phối phản hồi sự cố (Incident Response - IR) được kích hoạt bởi các cảnh báo, tận dụng việc thu thập dữ liệu song song và phân tích bằng Machine Learning (ML). Dự án được thiết kế để nén thời gian điều tra bằng cách thực hiện đồng thời các tác vụ thu thập dữ liệu độc lập.

## Các tính năng chính
- **Thu thập dữ liệu song song:** Chạy đồng thời các tác vụ Trinh sát (OSINT), Thu thập Log (Sysmon) và Phân tích mạng.
- **Phân loại bằng ML:** Nhận diện loại hình tấn công (ví dụ: Brute-force, Reconnaissance) bằng các mô hình đã huấn luyện.
- **Ánh xạ MITRE ATT&CK:** Ánh xạ các hành vi và bằng chứng phát hiện được vào khung kỹ thuật chuẩn MITRE.
- **Tự động lập báo cáo:** Sinh báo cáo IR có cấu trúc bao gồm bối cảnh, bằng chứng và các bước ngăn chặn.

## Cấu trúc đường ống (Pipeline)
1. **Orchestrator (Người điều phối):** Phân tích các cảnh báo kích hoạt ban đầu (ví dụ: Suricata) và điều phối các Agent cấp dưới.
2. **Giai đoạn 1 (Các Agent song song):**
    - **Recon Agent:** Đánh giá uy tín IP qua OSINT (VirusTotal, AbuseIPDB, v.v.).
    - **Log Collector:** Tìm kiếm các bất thường trên máy chủ trong log Sysmon quanh thời điểm xảy ra cảnh báo.
    - **Network Analyzer:** Tổng hợp và phân tích các luồng đa giao thức (HTTP, DNS, SMB, v.v.).
3. **Giai đoạn 2 (Tổng hợp):**
    - Trích xuất đặc trưng và phân loại bằng ML.
    - Ánh xạ MITRE ATT&CK dựa trên bằng chứng tổng hợp.
    - Xuất báo cáo IR hoàn chỉnh (hỗ trợ bởi LLM).

## Nguồn dữ liệu
- **Splunk BOTSv1 (Boss of the SOC v1):**
    - `alerts_trigger_botsv1.json` (Dữ liệu Suricata)
    - `sysmon_logs_botsv1.json` (Dữ liệu Sysmon)
    - `network_streams_botsv1.json` (Dữ liệu luồng mạng - Stream data)
