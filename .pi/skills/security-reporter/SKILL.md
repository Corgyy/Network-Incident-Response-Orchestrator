---
name: security-reporter
description: >
  Dùng khi cần tạo báo cáo bảo mật tổng hợp từ các file tcp.json,
  dns.json, ssh.json. Phân tích và đưa ra nhận định về security.
  Xuất báo cáo Markdown.
  Triggers on: tạo báo cáo bảo mật, security report, tổng hợp kết quả,
  generate security report, phân tích bảo mật tổng hợp.
---

# Security Reporter

Đọc tcp.json, dns.json, ssh.json và tạo báo cáo bảo mật tổng hợp
với nhận định về các mối đe dọa.

## Usage

```bash
python3 <skill_dir>/generate_report.py \
  --tcp <output_dir>/tcp.json \
  --dns <output_dir>/dns.json \
  --ssh <output_dir>/ssh.json \
  --output <output_dir>/security_report.md \
  [--title "Báo cáo phân tích PCAP"]
```

## Output

File Markdown với các section:
1. Tóm tắt điều hành (Executive Summary)
2. Phân tích TCP — cổng bất thường, lưu lượng cao
3. Phân tích DNS — suspicious domains, DGA candidates
4. Phân tích SSH — brute force suspects
5. Nhận định bảo mật tổng hợp
6. Khuyến nghị

## Notes

- Tất cả 3 file input phải tồn tại trước khi chạy
- Dừng và báo lỗi rõ ràng nếu thiếu bất kỳ file nào
- Nhận định dựa trên dữ liệu thực tế trong các JSON file