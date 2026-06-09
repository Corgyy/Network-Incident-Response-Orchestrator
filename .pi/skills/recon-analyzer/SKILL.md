---
name: recon-analyzer
description: Tình báo OSINT - Tự động tra cứu danh tiếng cho IP, Tên miền hoặc Mã băm qua VirusTotal.
parameters:
  ioc:
    type: string
    description: "Chỉ số xâm nhập (Địa chỉ IP, Tên miền, hoặc Mã băm tệp)."
    required: true
  output:
    type: string
    description: "Đường dẫn lưu kết quả OSINT JSON."
    required: true
  vt_key:
    type: string
    description: "VirusTotal API Key."
    default: "00fa140d20875f2330e3065f67865979254a1bd1854c557ca7caf495838b4230"
outputs:
  ioc_type:
    type: string
    description: "Loại IOC được phát hiện (ip, domain, hoặc hash)."
  malicious_engines:
    type: integer
    description: "Số lượng nhà cung cấp gắn cờ IOC là độc hại."
  is_malicious:
    type: boolean
    description: "Phán quyết cuối cùng dưới dạng Boolean."
---

# Skill Phân tích Trinh sát (Đồng bộ)

## Tổng quan & Khả năng
Cung cấp ngữ cảnh bên ngoài cho các cảnh báo nội bộ bằng cách sử dụng **VirusTotal V3 API**.
- **Logic Tự động Phát hiện:** Sử dụng Regex mạnh mẽ để phân biệt giữa IPv4, Tên miền và các mã băm MD5/SHA256.
- **Tình báo Toàn cầu:** Lấy điểm danh tiếng và thống kê phát hiện độc hại từ hơn 70 nhà cung cấp bảo mật.
- **Tính tương thích Môi trường:** Sử dụng thư viện `requests` để thực thi đồng bộ mà không cần thêm phụ thuộc phức tạp.

## Cú pháp Thực thi
```bash
python3 ./.pi/skills/recon-analyzer/analyze_recon.py \
  --ioc "EC78C938D8453739CA2A370B9C275971EC46CAF6E479DE2B2D04E97CC47FA45D" \
  --output "./reports/recon_hash_result.json"
```

## Cấu trúc Đầu ra
```json
{
  "ioc": "...",
  "ioc_type": "hash",
  "malicious_engines": 66,
  "vt_reputation_score": -15,
  "is_malicious": true
}
```

## Ràng buộc Vận hành
- **CẢNH BÁO NGHIÊM TRỌNG:** Kết quả có 0 công cụ độc hại **KHÔNG** có nghĩa là đối tượng đó an toàn. Nhiều kẻ tấn công sử dụng hạ tầng mới. Bạn **BẮT BUỘC** phải tiếp tục điều tra vào log nội bộ (Sàng lọc & Thu thập) theo Playbook IR. Không bao giờ kết luận điều tra chỉ dựa trên công cụ này.
- **Giới hạn API:** Lưu ý hạn ngạch API VirusTotal của bạn (tiêu chuẩn là 4 yêu cầu/phút).
