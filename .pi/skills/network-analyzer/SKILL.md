---
name: network-protocol-analyzer
description: Trích xuất đặc trưng luồng mạng hiệu suất cao sử dụng bộ lọc Grep-First.
parameters:
  src_ip:
    type: string
    description: "IP nguồn cần phân tích (thường là kẻ tấn công)."
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
    description: "Đường dẫn đến log network stream."
    default: "./data/network_streams_botsv1.json"
  output_file:
    type: string
    description: "Đường dẫn lưu kết quả mạng JSON."
    default: "./reports/network_analyzer_result.json"
outputs:
  feature_vector:
    type: object
    description: "Các số liệu luồng được tổng hợp (byte, gói tin, tỷ lệ)."
  analysis_summary:
    type: string
    description: "Tóm tắt hành vi mạng dưới dạng ngôn ngữ tự nhiên."
---

# Skill Phân tích Giao thức Mạng

## Cú pháp Thực thi
```bash
python3 ./.pi/skills/network-analyzer/analyze_network.py \
  --src-ip "40.80.148.42" \
  --target-timestamp "2016-08-10T15:36:48Z" \
  --window 55 \
  --output-file "./reports/network_analyzer_result.json"
```

## Ràng buộc Vận hành
- **Đường dẫn Tương đối:** Luôn sử dụng đường dẫn tương đối bắt đầu bằng `./`.
