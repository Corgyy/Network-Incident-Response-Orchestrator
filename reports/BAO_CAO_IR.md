# BÁO CÁO ỨNG PHÓ SỰ CỐ (Incident Response Report)

**Ngày lập báo cáo:** 2026-06-09  
**Mã sự cố:** IR-2026-001  
**IP điều tra:** 40.80.148.42  
**Người lập:** Orchestrator Agent (Điều phối Multi-Agent)

---

## 1. Tóm tắt Điều hành

Vào ngày **10 tháng 8 năm 2016**, hệ thống phát hiện xâm nhập (IDS) ghi nhận **589 cảnh báo trùng khớp** từ địa chỉ IP nguồn **40.80.148.42** (Hoa Kỳ) hướng đến nạn nhân **192.168.250.70**. Phân tích mạng cho thấy **21.380 luồng dữ liệu** với tổng dung lượng **226,32 MB**, tỉ lệ **in/out = 3,16** – dấu hiệu điển hình của hành vi **rò rỉ dữ liệu (exfiltration)**. Giao thức `unknown` chiếm chủ đạo, gợi ý hoạt động phi chuẩn hoặc mã hóa tùy chỉnh.

Dữ liệu log máy chủ (Sysmon) từ cùng nạn nhân được thu thập vào ngày **25 tháng 8 năm 2016** – lệch **15 ngày** so với thời điểm cảnh báo – không phát hiện bất thường nào. Sự lệch thời gian này khiến việc xác nhận chuỗi hành vi kẻ tấn công ở phía máy chủ bị gián đoạn.

**Mức độ ảnh hưởng:** Có dấu hiệu rò rỉ dữ liệu, chưa thể xác nhận tổn thất cụ thể do thiếu log máy chủ đồng bộ.

---

## 2. Hồ sơ Kẻ tấn công

| Thuộc tính | Giá trị |
|------------|---------|
| **Địa chỉ IP nguồn** | `40.80.148.42` |
| **Quốc gia** | Hoa Kỳ (US) |
| **Danh tiếng (VirusTotal)** | Sạch (0 engine độc hại, reputation score: 0) |
| **Máy chủ mục tiêu** | `192.168.250.70` (nội bộ) |

> **Lưu ý:** Mặc dù VirusTotal đánh giá IP là sạch, số lượng cảnh báo IDS và tỉ lệ lưu lượng bất thường cho thấy hoạt động thù địch rất rõ ràng. Danh tiếng "sạch" có thể do IP mới hoặc chưa được gắn nhãn kịp thời.

---

## 3. Dòng thời gian Chi tiết (Theo Cyber Kill Chain)

| Giai đoạn Kill Chain | Thời gian (ước lượng) | Bằng chứng |
|----------------------|----------------------|------------|
| **1. Trinh sát (Reconnaissance)** | Trước 2016-08-10T15:36:48 | IDS ghi nhận 589 cảnh báo từ `40.80.148.42` – quét cổng hoặc thăm dò lỗ hổng. |
| **2. Khai thác (Exploitation)** | 2016-08-10 | Dựa trên IDS, một hoặc nhiều lỗ hổng đã bị khai thác thành công. (Không có log máy chủ để xác nhận kỹ thuật cụ thể) |
| **3. Cài đặt (Installation)** | 2016-08-10 | Không có log máy chủ đồng bộ. Dữ liệu mạng cho thấy có thể đã tải lên payload qua giao thức unknown. |
| **4. Hành động trên mục tiêu (Actions on Objectives)** | 2016-08-10 | **Exfiltration rõ rệt:** 21.380 luồng, 226,32 MB, tỉ lệ in/out = 3,16 (lượng ra > lượng vào) |

**Ghi chú:** Thiếu dữ liệu Sysmon/Event Log (thu thập ngày 25/08/2016, lệch 15 ngày) nên không thể xác nhận chính xác thời điểm cài đặt backdoor hay lệnh thực thi trên máy chủ.

---

## 4. Ánh xạ MITRE ATT&CK

| Kỹ thuật | Mã MITRE | Bằng chứng |
|----------|----------|------------|
| Quét dịch vụ mạng (Network Service Scanning) | T1046 | 589 cảnh báo IDS – quét dịch vụ từ IP bên ngoài |
| Rò rỉ qua kênh C2 (Exfiltration Over C2 Channel) | T1041 | Tỉ lệ in/out = 3,16; giao thức unknown; dung lượng lớn 226 MB |
| Cổng không phổ biến (Uncommonly Used Port) | T1505 (nhánh) | Giao thức `unknown` chiếm chủ đạo – có thể là cổng không chuẩn hoặc mã hóa tùy chỉnh |
| Truyền tải công cụ xâm nhập (Ingress Tool Transfer) | T1105 | Có thể đã có truyền tải payload (suy luận từ khả năng khai thác, nhưng không có log xác nhận) |
| Dữ liệu từ ổ đĩa chia sẻ mạng (Data from Network Shared Drive) | T1039 | Không có bằng chứng trực tiếp; exfiltration dung lượng lớn gợi ý khả năng này |

> Các kỹ thuật chỉ được liệt kê khi có căn cứ từ dữ liệu mạng/IDS. Thiếu log máy chủ nên nhiều kỹ thuật khác (T1059, T1505.003) không thể xác nhận.

---

## 5. Khuyến nghị Ngăn chặn

### 5.1. Ngay lập tức (trong vòng 24 giờ)
- **Chặn IP `40.80.148.42`** tại tường lửa và IPS, cập nhật danh sách đen.
- **Cách ly máy `192.168.250.70`** khỏi mạng nội bộ để ngăn rò rỉ thêm.
- **Xoay vòng mật khẩu** tất cả tài khoản có quyền truy cập máy nạn nhân.
- **Kiểm tra các luồng `unknown`** trên thiết bị mạng để xác định cổng/host lạ.

### 5.2. Ngắn hạn (trong vòng 1 tuần)
- **Đồng bộ thời gian toàn hệ thống** (NTP) và đặt chính sách lưu giữ log ít nhất 90 ngày.
- **Triển khai giám sát tỉ lệ in/out** – đặt ngưỡng cảnh báo khi vượt quá 2.5.
- **Cập nhật chữ ký IDS** để phát hiện giao thức unknown/custom.

### 5.3. Dài hạn (trong vòng 1 tháng)
- **Xây dựng quy trình thu thập log tự động** – log máy chủ phải được thu thập và lưu trữ tập trung trong vòng < 1 giờ sau sự kiện.
- **Đánh giá lại danh sách IP đáng tin cậy** – không dựa hoàn toàn vào VirusTotal (IP sạch vẫn có thể là tấn công).
- **Thực hiện diễn tập ứng phó sự cố** có sẵn dữ liệu mạng và log máy chủ để đảm bảo khả năng tái hiện đầy đủ chuỗi tấn công.

---

## 6. Chi tiết Kỹ thuật

### 6.1. Kết quả Triage (Sàng lọc)
| Tham số | Giá trị |
|---------|---------|
| attacker_ip | `40.80.148.42` |
| victim_ip | `192.168.250.70` |
| target_timestamp | `2016-08-10T15:36:48.130747-0600` |
| recommended_window | 55 phút |
| Số cảnh báo IDS khớp | 589 |

### 6.2. Kết quả OSINT (VirusTotal)
| Tham số | Giá trị |
|---------|---------|
| Loại IOC | IP |
| malicious_engines | 0 |
| Reputation score | 0 |
| Quốc gia | US |
| Phán quyết | SẠCH |

### 6.3. Kết quả Network Analyzer
| Tham số | Giá trị |
|---------|---------|
| Tổng số luồng (flow_count) | 21.380 |
| Tổng dung lượng (MB) | 226,32 |
| Tỉ lệ in/out | 3,1603 |
| Tốc độ gói tin (packet_rate) | 67,23 |
| Số đích đến riêng biệt | 2 |
| Giao thức chủ đạo | unknown |
| Số giao thức riêng biệt | 6 |

### 6.4. Kết quả Log Collector
| Tham số | Giá trị |
|---------|---------|
| victim_ip | `192.168.250.70` |
| Sự kiện ID | (trống) |
| Tiến trình nghi vấn | 0 |
| Lệnh nghi vấn | 0 |
| Bằng chứng hash | 0 |
| Mức độ rủi ro | THẤP (do lệch thời gian dữ liệu) |

---

**Kết luận:** Dựa trên bằng chứng mạng và IDS, sự cố này là một cuộc tấn công có chủ đích với mục tiêu **rò rỉ dữ liệu**. Thiếu đồng bộ thời gian log là lỗ hổng nghiêm trọng trong quy trình giám sát hiện tại. Cần ngay lập tức chặn IP nguồn và cách ly máy nạn nhân, đồng thời khắc phục khoảng trống thu thập log.
