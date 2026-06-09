---
name: ml-classifier
description: Phát hiện bất thường bằng IsolationForest, gán loại sự cố, ánh xạ MITRE ATT&CK và xuất kết quả phân loại incident.
parameters:
  log_file:
    type: string
    description: "Đường dẫn đến output JSON của Log Collector."
    default: "./reports/log_collector_result.json"
  network_file:
    type: string
    description: "Đường dẫn tùy chọn đến output JSON của Network Analyzer."
    required: false
    default: ""
  model_file:
    type: string
    description: "Đường dẫn đến model IsolationForest đã train."
    default: "./.pi/models/isolation_forest_model.pkl"
  output_file:
    type: string
    description: "Đường dẫn lưu kết quả ML classification."
    default: "./reports/ml_classification_result.json"
outputs:
  anomaly_label:
    type: string
    description: "Kết quả phát hiện bất thường: normal hoặc anomaly."
  anomaly_score:
    type: number
    description: "Điểm bất thường từ IsolationForest."
  predicted_incident_type:
    type: string
    description: "Loại sự cố được gán nhãn sau khi kết hợp ML anomaly detection và rule-based labeling."
  severity:
    type: string
    description: "Mức độ nghiêm trọng: low, medium, high."
  feature_vector:
    type: object
    description: "Vector đặc trưng được trích xuất từ Log Collector và Network Analyzer."
  mitre_mapping:
    type: array
    description: "Danh sách kỹ thuật MITRE ATT&CK được ánh xạ từ evidence."
  analysis_summary:
    type: string
    description: "Tóm tắt kết quả phân loại."
---

# ML Classifier Skill

Skill này triển khai giai đoạn Machine Learning Classification trong Network Incident Response Orchestrator.

## Mục tiêu

- Đọc output từ Log Collector.
- Đọc output từ Network Analyzer nếu có.
- Trích xuất feature vector.
- Dùng model IsolationForest đã train để phát hiện anomaly.
- Gán loại incident như Web Shell Malware Execution, Network Anomaly, DNS Anomaly, Reconnaissance, Brute Force.
- Map kết quả sang MITRE ATT&CK.
- Ghi kết quả vào thư mục `./reports/`.

## Train model

```bash
python ./.pi/skills/ml-classifier/train_model.py \
  --training-file "./.pi/data/training_incidents.csv" \
  --model-file "./.pi/models/isolation_forest_model.pkl" \
  --report-file "./reports/ml_training_report.json" \
  --contamination 0.25