---
name: log-collector
description: Thu thập bằng chứng máy chủ tối ưu sử dụng chiến lược Grep-First.
parameters:
  dest_ip:
    type: string
    description: "Địa chỉ IP nạn nhân cần điều tra."
    required: true
  target_timestamp:
    type: string
    description: "Dấu thời gian gốc theo định dạng ISO/Splunk."
    required: true
  window:
    type: integer
    description: "Bán kính tìm kiếm tính bằng phút (+/-)."
    default: 5
  input_file:
    type: string
    description: "Đường dẫn đến log Sysmon NDJSON."
    default: "./data/sysmon_logs_botsv1.json"
  output_file:
    type: string
    description: "Đường dẫn lưu kết quả JSON."
    default: "./reports/log_collector_result.json"
outputs:
  analysis_summary:
    type: string
    description: "Tóm tắt các phát hiện nghi vấn dưới dạng ngôn ngữ tự nhiên."
  risk_level:
    type: string
    description: "Đánh giá rủi ro cuối cùng (high/low)."
---

# Skill Thu thập Log

## Cú pháp Thực thi
```bash
python3 ./.pi/skills/log-collector/collect_logs.py \
  --dest-ip "192.168.250.70" \
  --target-timestamp "2016-08-10T15:36:48Z" \
  --window 60 \
  --input-file "./data/sysmon_logs_botsv1.json"
```

## Ràng buộc Vận hành
- **Đường dẫn Mặc định:** Hiện tại trỏ đến `./data/sysmon_logs_botsv1.json`.
