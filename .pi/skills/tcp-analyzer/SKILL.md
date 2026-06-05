---
name: tcp-analyzer
description: >
  Dùng khi cần phân tích TCP streams từ file PCAP, thống kê số lượng
  TCP stream, tổng byte gửi/nhận, thời lượng mỗi stream, các cổng
  phổ biến. Xuất kết quả ra tcp.json.
  Triggers on: phân tích TCP, TCP streams, thống kê TCP,
  analyze TCP, TCP statistics, parse TCP từ PCAP.
---

# TCP Analyzer

Đọc file PCAP bằng tshark, tổng hợp các TCP stream và xuất tcp.json.

## Usage

```bash
python3 /analyze_tcp.py \
  --input  \
  --output /tcp.json
```

## Output Schema

```json
{
  "timestamp": "...",
  "source_pcap": "...",
  "summary": {
    "total_streams": 42,
    "total_bytes_sent": 123456,
    "total_bytes_received": 654321,
    "top_dst_ports": {"80": 10, "443": 8}
  },
  "streams": [
    {
      "stream_id": 0,
      "src_ip": "192.168.1.1",
      "dst_ip": "192.168.1.2",
      "src_port": 54321,
      "dst_port": 80,
      "bytes_sent": 1234,
      "bytes_received": 5678,
      "packets": 12,
      "duration": 2.34,
      "state": "closed"
    }
  ]
}
```

## Notes

- Yêu cầu tshark đã cài (`sudo apt install tshark`)
- Phân tích theo tcp.stream index của tshark
- state: closed (FIN/RST seen), open (chưa kết thúc)