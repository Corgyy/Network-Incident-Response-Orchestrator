---
name: ml-classifier
description: "Phân loại loại sự cố bằng RandomForestClassifier, kết hợp evidence từ Log Collector và Network Analyzer, sau đó ánh xạ MITRE ATT&CK."

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
    description: "Đường dẫn đến model RandomForestClassifier đã train."
    default: "./.pi/models/random_forest_incident_classifier.pkl"

  output_file:
    type: string
    description: "Đường dẫn lưu kết quả ML classification."
    default: "./reports/ml_classification_result.json"

outputs:
  predicted_incident_type:
    type: string
    description: "Loại sự cố được RandomForestClassifier dự đoán."

  classification_confidence:
    type: number
    description: "Độ tin cậy của kết quả phân loại."

  class_probabilities:
    type: object
    description: "Xác suất dự đoán cho từng loại incident."

  severity:
    type: string
    description: "Mức độ nghiêm trọng: low, medium, high."

  feature_vector:
    type: object
    description: "Vector đặc trưng được trích xuất từ Log Collector và Network Analyzer."

  mitre_mapping:
    type: array
    description: "Danh sách kỹ thuật MITRE ATT&CK được ánh xạ từ evidence."

  summary:
    type: string
    description: "Tóm tắt kết quả phân loại."
---

# ML Classifier Skill

Skill này triển khai giai đoạn Machine Learning Classification trong Network Incident Response Orchestrator.

## Mục tiêu

* Đọc output từ Log Collector.
* Đọc output từ Network Analyzer nếu có.
* Trích xuất feature vector.
* Dùng model RandomForestClassifier đã train để phân loại loại sự cố.
* Dự đoán incident type như Web Shell Malware Execution, Network Anomaly, DNS Anomaly, Reconnaissance, Brute Force, Malware Execution.
* Tính classification confidence.
* Map kết quả sang MITRE ATT&CK.
* Ghi kết quả vào thư mục `./reports/`.

## Vai trò của Machine Learning

Pipeline được kích hoạt bởi một alert, vì vậy ML không dùng để phát hiện alert ban đầu.

ML được dùng để phân loại alert sau khi Log Collector và Network Analyzer đã trích xuất feature. RandomForestClassifier học từ `training_incidents.csv` để dự đoán loại incident dựa trên feature vector.

## Train model

```bash
python ./.pi/skills/ml-classifier/train_model.py \
  --training-file "./data/training_incidents.csv" \
  --model-file "./.pi/models/random_forest_incident_classifier.pkl" \
  --report-file "./reports/ml_training_report.json"
```

## Classify incident

```bash
python ./.pi/skills/ml-classifier/classify_incident.py \
  --log-file "./reports/log_collector_result.json" \
  --network-file "./reports/network_analyzer_result.json" \
  --model-file "./.pi/models/random_forest_incident_classifier.pkl" \
  --output-file "./reports/ml_classification_result.json"
```

## Example: Web Shell 3791.exe

```bash
python ./.pi/skills/ml-classifier/classify_incident.py \
  --log-file "./reports/log_collector_3791.json" \
  --network-file "./reports/network_analyzer_3791.json" \
  --model-file "./.pi/models/random_forest_incident_classifier.pkl" \
  --output-file "./reports/ml_classification_3791.json"
```

## Output

Output được lưu dưới dạng JSON trong `./reports/`, gồm:

* predicted_incident_type
* classification_confidence
* class_probabilities
* severity
* feature_vector
* evidence_used
* mitre_mapping
* summary
