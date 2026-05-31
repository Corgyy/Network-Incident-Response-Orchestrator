# TÀI LIỆU HƯỚNG DẪN THỰC HIỆN ĐỀ TÀI

**Tên đề tài:** Network Incident Response Orchestrator  
**Nguồn dữ liệu:** Splunk BOTSv1 (Boss of the SOC version 1)

---

## PHẦN 1: TỔNG QUAN ĐỀ TÀI

### 1. Mô tả ngắn gọn
Xây dựng một đường ống phản hồi sự cố (IR pipeline) tự động, được kích hoạt bằng một cảnh báo (alert). Hệ thống sẽ chạy song song các tác vụ trinh sát (Recon), thu thập log, và trích xuất đặc trưng PCAP/Network. Sau đó, hệ thống sử dụng Machine Learning để phân loại sự cố, ánh xạ vào framework MITRE ATT&CK và xuất ra báo cáo IR có cấu trúc kèm theo các bước khắc phục.

### 2. Lợi ích của kiến trúc chạy song song (Parallelism)
Việc thu thập Recon, Log và trích xuất Network Feature là 3 tác vụ thu thập dữ liệu hoàn toàn độc lập. Việc đưa chúng vào Stage 1 chạy song song giúp nén thời gian điều tra từ 3 bước tuần tự xuống chỉ còn 1 bước. Ở Stage 2, hệ thống tiếp tục song song hóa việc chấm điểm ML trên các luồng dữ liệu độc lập.

---

## PHẦN 2: CHUẨN BỊ DỮ LIỆU (Dữ liệu mẫu từ BOTSv1)

1. **Cảnh báo ban đầu (Trigger):** `alerts_trigger_botsv1.json` (Export từ `sourcetype=suricata`)
2. **Dữ liệu cho Log Agent:** `sysmon_logs_botsv1.json` (Export từ `sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"`)
3. **Dữ liệu cho PCAP/Network Agent:** `network_streams_botsv1.json` (Export từ `sourcetype="stream:*"` - bao gồm TCP, UDP, HTTP, DNS, SMB, ICMP, TLS,...)

*Lưu ý: Việc sử dụng `stream:*` cho phép hệ thống phân tích toàn diện các giao thức mạng, từ đó phát hiện được cả các hành vi di chuyển ngang hàng (Lateral Movement) và các kênh điều khiển (C2) tinh vi. Có thể sử dụng các LLM API key như Gemini, ChatGPT, DeepSeek,... để hỗ trợ quá trình phân tích và tạo báo cáo.*

---

## PHẦN 3: KIẾN TRÚC HỆ THỐNG VÀ LUỒNG DỮ LIỆU

### BƯỚC 0: Orchestrator (Người Điều Phối)
*   **Hành động:** Đọc file `alerts_trigger_botsv1.json`.
*   **Thông tin trích xuất:** Lấy ra `src_ip` (IP tấn công), `dest_ip` (IP nạn nhân) và `timestamp` (thời điểm xảy ra cảnh báo).
*   **Phân phát:** Đóng gói các thông tin này và truyền đồng thời cho 3 Agent bên dưới.

### BƯỚC 1: STAGE 1 - Hoạt động song song của 3 Agent

#### 1. Agent 1: Recon (Tác tử Trinh sát - OSINT)
*   **Input:** `src_ip` (nhận từ Orchestrator).
*   **Nhiệm vụ:** Không đọc file nội bộ. Gửi API ra Internet (VirusTotal, AbuseIPDB, OTX).
*   **Output trả về:** Điểm số uy tín (Reputation Score), phân loại mối đe dọa (Scanner, C2, Botnet) và vị trí địa lý của IP.

#### 2. Agent 2: Log Collector (Tác tử Thu thập Nhật ký)
*   **Input:** File `sysmon_logs_botsv1.json` + `timestamp` & `dest_ip` (từ Orchestrator).
*   **Nhiệm vụ:** Tìm kiếm các hành vi bất thường trên máy nạn nhân trong khoảng thời gian `timestamp ± 5 phút`.
*   **Output trả về:** Danh sách các tiến trình lạ vừa khởi tạo (EventID 1), các dòng lệnh khả nghi (VD: PowerShell), và kết nối mạng tạo bởi các tiến trình (EventID 3).

#### 3. Agent 3: Multi-Protocol Network Analyzer (Phân tích mạng đa giao thức)
*   **Input:** File `network_streams_botsv1.json` (`stream:*`) + `src_ip` & `timestamp` (từ Orchestrator).
*   **Nhiệm vụ:** 
    *   Hợp nhất dữ liệu từ nhiều giao thức (HTTP, DNS, SMB, TCP...).
    *   Gom nhóm (Aggregate) các luồng giao tiếp liên quan đến thực thể tấn công.
    *   Trích xuất đặc trưng đa tầng: Tần suất kết nối (TCP/UDP), dấu hiệu bất thường trong tên miền (DNS), hành vi truyền file/truy cập share (SMB), và các chỉ số ứng dụng (HTTP).
*   **Output trả về (Enhanced Feature Vector):** Tổng hợp các chỉ số định lượng và định tính về hành vi mạng của đối tượng.

### BƯỚC 2: STAGE 2 - Tổng hợp, Phân tích ML và Báo cáo

1. **Phân loại ML (ML Classification):** Đưa mảng đặc trưng (Feature Vector) từ Agent 3 vào mô hình Machine Learning đã huấn luyện (VD: Random Forest) để nhận diện loại hình tấn công (Brute-force, Reconnaissance, v.v.).
2. **Ánh xạ MITRE ATT&CK:** Kết hợp bằng chứng lệnh thực thi từ Agent 2 và loại tấn công từ ML để map vào các mã kỹ thuật MITRE (VD: T1059 - Command and Scripting Interpreter).
3. **Xuất báo cáo (Report Generation):** Sinh ra một báo cáo IR hoàn chỉnh bao gồm bối cảnh sự cố, các bằng chứng thu thập được, loại hình tấn công và đề xuất các bước ngăn chặn (Containment Steps). Có thể sử dụng LLM (Gemini, ChatGPT...) để làm phong phú nội dung và đề xuất giải pháp.
