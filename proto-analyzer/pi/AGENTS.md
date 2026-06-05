# PCAP Analysis Orchestrator

Bạn điều phối pipeline phân tích PCAP gồm 4 agent.
Agent tcp-agent, dns-agent, ssh-agent chạy SONG SONG. Agent report-agent chờ tất cả hoàn tất.

## Pipeline
           ┌─ tcp-agent  (→ tcp.json)  ─┐
PCAP ──────┼─ dns-agent  (→ dns.json)  ─┼──→ report-agent (→ report.md)
           └─ ssh-agent  (→ ssh.json)  ─┘

## File PCAP input
Đường dẫn PCAP do người dùng cung cấp trong task.
Mặc định: ~/proto-analyzer/input/captures.pcap

## Output directory
~/proto-analyzer/output/

## Cách thực thi với pi-subagents

Bước 1: Dispatch SONG SONG 3 subagents:
- tcp-agent  với PCAP đã cho → chờ xuất tcp.json
- dns-agent  với PCAP đã cho → chờ xuất dns.json
- ssh-agent  với PCAP đã cho → chờ xuất ssh.json

Bước 2: CHỜ cả 3 hoàn tất (kiểm tra sự tồn tại của 3 file JSON)

Bước 3: Dispatch report-agent với 3 file JSON làm input

## Dispatch mode
Dùng **parallel** cho bước 1 (tcp, dns, ssh cùng lúc).
Dùng **single** cho bước 2 (reporter sau khi 3 file tồn tại).

## Kiểm tra hoàn tất
Trước khi chạy reporter-agent, verify:
- output/tcp.json tồn tại và không rỗng
- output/dns.json tồn tại và không rỗng
- output/ssh.json tồn tại và không rỗng
Nếu thiếu file nào → báo agent nào chưa hoàn tất.

## Khi thất bại một agent song song
Nếu tcp-agent, dns-agent hoặc ssh-agent thất bại:
- Báo cáo agent nào thất bại và lý do
- Vẫn tiếp tục các agent còn lại
- Không chạy reporter-agent nếu bất kỳ file nào thiếu