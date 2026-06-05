---
name: ssh-analyzer
description: >
  Dùng khi cần phân tích SSH flows từ PCAP, thống kê các SSH session,
  phát hiện brute force, thống kê byte trao đổi, thời lượng session.
  Xuất kết quả ra ssh.json.
  Triggers on: phân tích SSH, SSH flows, SSH sessions, thống kê SSH,
  analyze SSH, SSH statistics, SSH brute force từ PCAP.
---

# SSH Analyzer

Đọc file PCAP, lọc TCP port 22, tổng hợp SSH sessions và
phát hiện dấu hiệu brute force.

## Usage

```bash
python3 <skill_dir>/analyze_ssh.py \
  --input <pcap_file> \
  --output <output_dir>/ssh.json
```

## Output Schema

```json
{
  "timestamp": "...",
  "source_pcap": "...",
  "summary": {
    "total_ssh_flows": 15,
    "unique_src_ips": 5,
    "unique_dst_ips": 2,
    "total_bytes": 234567,
    "avg_session_duration": 45.2,
    "brute_force_candidates": 2
  },
  "brute_force_suspects": [
    {
      "src_ip": "192.168.1.100",
      "target_ip": "192.168.1.10",
      "connection_attempts": 25,
      "short_sessions": 24,
      "avg_duration": 0.8,
      "verdict": "likely brute force"
    }
  ],
  "sessions": [
    {
      "stream_id": 5,
      "src_ip": "192.168.1.1",
      "dst_ip": "192.168.1.2",
      "src_port": 54321,
      "bytes_sent": 1234,
      "bytes_received": 5678,
      "duration": 120.5,
      "verdict": "normal"
    }
  ]
}
```

## Notes

- SSH flows xác định bằng TCP dst_port == 22 hoặc src_port == 22
- Brute force: >= 5 connections ngắn (< 5 giây) từ cùng src_ip
- duration ngắn + nhiều kết nối = dấu hiệu brute force