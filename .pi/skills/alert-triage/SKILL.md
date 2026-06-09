---
name: alert-triage-agent
description: Bước 0 của Quy trình - Phân tích các cảnh báo đa nguồn để thiết lập ngữ cảnh và dòng thời gian sự cố.
parameters:
  ioc:
    type: string
    description: "Chỉ số xâm nhập (IP, Tên miền, Chữ ký, hoặc Tên tệp) cần sàng lọc."
    required: true
  alert_file:
    type: string
    description: "Đường dẫn đến tệp cảnh báo Suricata IDS."
    default: "./data/alerts_trigger_botsv1.json"
  sysmon_file:
    type: string
    description: "Đường dẫn đến tệp log máy chủ Sysmon."
    default: "./data/sysmon_logs_botsv1.json"
outputs:
  triage_context:
    type: object
    description: "Ngữ cảnh điều phối đã tính toán bao gồm vai trò suy luận, dòng thời gian và các tham số cho bước tiếp theo."
---

# Skill Sàng lọc Cảnh báo (Tối ưu hóa)

## Tổng quan & Khả năng
Skill này đóng vai trò là **bộ điều phối chính (Bước 0)**.
- **Phát hiện Lệch thời gian:** Tự động so sánh dấu thời gian cảnh báo với phạm vi log máy chủ và đưa ra cảnh báo nghiêm trọng nếu ngày tháng không khớp.
- **Suy luận Vai trò:** Xác định vai trò Kẻ tấn công (Attacker) và Nạn nhân (Victim).
- **Phạm vi Động:** Tính toán chính xác cửa sổ thời gian điều tra.

## Cú pháp Thực thi
```bash
python3 ./.pi/skills/alert-triage/triage_alerts.py --ioc "40.80.148.42"
```

## Ràng buộc Vận hành
- **Đường dẫn Tiêu chuẩn:** Mặc định sử dụng cấu trúc thư mục `./data/`.
- **Kiểm tra Tính hợp lệ:** Nếu cảnh báo `CRITICAL TIME MISMATCH` được trả về, agent phải thông báo cho người dùng rằng việc thu thập log cho ngày này có thể thất bại.
