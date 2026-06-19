# BẮT BUỘC ĐỐI VỚI AGENT (FOUNDATIONAL MANDATES)

## 1. QUY TẮC ĐƯỜNG DẪN (STRICT RELATIVE PATHS)
- **KHÔNG BAO GIỜ** sử dụng đường dẫn tuyệt đối (Ví dụ: KHÔNG dùng `E:\...`, `C:\...`, hay `/mnt/e/...`).
- **BẮT BUỘC** sử dụng đường dẫn tương đối bắt đầu bằng `./` từ thư mục gốc của project (Ví dụ: `./.pi/AGENT.md`, `./data/sysmon_logs_botsv1.json`).
- Mọi công cụ (`read_file`, `run_shell_command`, `list_directory`) đều phải tuân thủ quy tắc này.

## 2. QUY TRÌNH KHỞI ĐỘNG (STARTUP PROCEDURE)
- Ngay khi bắt đầu, hãy thực hiện lệnh `ls -R .pi/` để nắm bắt cấu trúc mà không cần mò mẫm.
- Đọc ngay file `./.pi/prompts/foundational_mandates.md` và `./.pi/AGENT.md` để hiểu vai trò "Nhạc trưởng" và quy trình IR Playbook.
- Không được dành quá 1 lượt (turn) để "khám phá" thư mục nếu cấu trúc đã rõ ràng.

## 3. THỰC THI NHIỆM VỤ
- Tuân thủ tuyệt đối mô hình **Direct Execution** đã quy định trong `./.pi/AGENT.md`.
- Ở Phase 2, bắt buộc gọi đồng thời 2 lệnh shell trong cùng một lượt phản hồi để thực thi song song thực sự.
- Luôn in kết quả trung gian ra màn hình TUI theo định dạng `[DEBUG]`, `[INFO]` như yêu cầu trong SOP.
