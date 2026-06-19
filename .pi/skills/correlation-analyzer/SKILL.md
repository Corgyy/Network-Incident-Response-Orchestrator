---
name: correlation-analyzer
description: Thực hiện so khớp chéo bằng chứng giữa máy chủ và mạng để xác định High-Fidelity IOCs.
parameters:
  log-file:
    type: string
    description: "Đường dẫn tới tệp kết quả của Log Collector (JSON)."
    required: true
  net-file:
    type: string
    description: "Đường dẫn tới tệp kết quả của Network Analyzer (JSON)."
    required: true
  triage-file:
    type: string
    description: "Đường dẫn tới tệp ngữ cảnh Triage (JSON)."
    required: true
  output:
    type: string
    description: "Đường dẫn lưu Manifest kết quả (JSON)."
    default: "./reports/pivot_manifest.json"
---

# Skill So khớp chéo Bằng chứng (Correlation Analyzer)

## Tổng quan
Skill này là "bộ não" phân tích của hệ thống IR, chuyên trách việc kết nối các điểm dữ liệu rời rạc từ các nguồn khác nhau thành một bức tranh toàn cảnh về sự cố.

## Khả năng cốt lõi
1. **Dynamic Artifact Discovery (Zero-Hardcode):** Tự động phát hiện IP và Domain từ dòng lệnh Sysmon bằng Regex.
2. **Cross-Evidence Correlation:** Tự động nâng mức độ tin cậy cho các thực thể xuất hiện đồng thời trên cả máy chủ và mạng.
3. **Entropy-based Scoring:** Ưu tiên các tên miền lạ (DGA) dựa trên độ hỗn loạn thông tin.
4. **Contextual Deduplication:** Loại bỏ nhiễu và trùng lặp thực thể một cách thông minh.

## Cú pháp thực thi
```bash
python3 ./.pi/skills/correlation-analyzer/correlation_analyzer.py \
  --log-file ./reports/log_collector_result.json \
  --net-file ./reports/network_analyzer_result.json \
  --triage-file ./reports/triage_context.json \
  --output ./reports/pivot_manifest.json
```
