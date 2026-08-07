# 📋 Danh sách Đầu việc (Checklist) - Day 11 Controlled Agent Security

---

### 📍 Checkpoint 0 — Cài đặt môi trường & Kiểm thử ban đầu
- [x] **Khởi tạo Virtual Environment & Cài phụ thuộc**:
  - [x] Khởi tạo `.venv` và kích hoạt virtual environment.
  - [x] Cài đặt danh sách thư viện từ `requirements.txt`.
- [x] **Thiết lập API Key**: Tạo file `.env` từ `.env.example` và dán `GOOGLE_API_KEY`.
- [x] **Chạy Baseline Tests**:
  - [x] Chạy Smoke Test: `pytest tests/smoke -q` *(5/5 passed)*.
  - [x] Chạy Public Test: `pytest tests/public -q` *(Thực thi thành công, 7 failed/2 passed đúng kỳ vọng starter code)*.

---

### 📍 Checkpoint 1 — Lọc & Chặn Prompt Injection (Input Guardrails)
*File thực hiện:* [`src/guardrails/input_guardrails.py`](file:///Users/dauquocduy/workspace/AI20K/lab/Day11_2A202601445_DauQuocDuy/src/guardrails/input_guardrails.py)

- [x] **TODO 1 (`detect_injection`)**:
  - [x] Chuẩn hóa chuỗi văn bản: dùng `unicodedata.normalize("NFKC", text)`, chuyển sang lowercase, lọc bỏ các ký tự vô hình/zero-width space (`\u200b`, `\u200c`, ...).
  - [x] Xây dựng các mẫu regex phát hiện Direct Injection & Indirect Injection (ví dụ: `ignore all previous instructions`, `reveal password`, `giả lập vai trò`, ...).
  - [x] Phân biệt dữ liệu email/RAG ngân hàng lành tính (không chặn nhầm câu hỏi tóm tắt hợp lệ).
- [x] **TODO 2 (`topic_filter`)**:
  - [x] Lọc bỏ các câu hỏi ngoài phạm vi hỗ trợ của ngân hàng VinBank.
- [x] **TODO 3 (`InputGuardrailPlugin`)**:
  - [x] Tích hợp `detect_injection` và `topic_filter` vào luồng `before_run` của ADK plugin để chặn request ngay từ đầu vào. *(PASSED 3/3 public tests)*

---

### 📍 Checkpoint 2 — Bảo vệ dữ liệu nhạy cảm & Kiểm soát Egress Action
*Files thực hiện:* [`src/guardrails/output_guardrails.py`](file:///Users/dauquocduy/workspace/AI20K/lab/Day11_2A202601445_DauQuocDuy/src/guardrails/output_guardrails.py) & [`src/assignment/pipeline.py`](file:///Users/dauquocduy/workspace/AI20K/lab/Day11_2A202601445_DauQuocDuy/src/assignment/pipeline.py)

- [x] **TODO 4 (`content_filter` trong `output_guardrails.py`)**:
  - [x] Lọc bỏ PII (Số điện thoại, Email, CMND/CCCD, Số thẻ).
  - [x] Lọc bỏ Secret/Credential (`admin123`, API Key dạng `sk-vinbank-...`, DB Host `db.vinbank.internal`).
  - [x] Thay thế bằng nhãn mask/redact dạng `[REDACTED]`. *(PASSED test_content_filter_redacts_secrets)*
- [x] **TODO 5 (`safety_judge_agent`)**:
  - [x] Cấu hình mô hình `LlmAgent` (`gemini-3.1-flash-lite`) đóng vai trò Judge kiểm tra ngữ nghĩa an toàn của câu trả lời.
- [x] **TODO 6 (`OutputGuardrailPlugin`)**:
  - [x] Áp dụng `content_filter` và `safety_judge_agent` trong hook `after_run`.
- [x] **TODO 8A (`is_egress_allowed` trong `pipeline.py`)**:
  - [x] Parse chính xác hostname từ URL target bằng `urlparse`. Chỉ cho phép hostname thuộc allowlist (`api.vinbank.example`).
  - [x] Từ chối subdomain mạo danh (vd: `api.vinbank.example.evil.com`) và external domain (`evil.example`).
  - [x] Kiểm tra payload gửi đi không chứa thông tin nhạy cảm/secret. *(PASSED test_egress_policy_blocks_sensitive_payload_and_unknown_destination)*
- [ ] **TODO 7 (`nemo_guardrails.py`)** *(Tùy chọn/Nâng cao)*:
  - [ ] Định nghĩa các quy tắc Colang quản lý hội thoại ngân hàng an toàn.

---

### 📍 Checkpoint 3 — Cấu hình Human-In-The-Loop (HITL) cho hành động rủi ro
*File thực hiện:* [`src/hitl/hitl.py`](file:///Users/dauquocduy/workspace/AI20K/lab/Day11_2A202601445_DauQuocDuy/src/hitl/hitl.py)

- [x] **TODO 11 (`ConfidenceRouter.route`)**:
  - [x] `Confidence ≥ 0.90` và hành động thường ➔ Route: `auto_send`.
  - [x] `Confidence 0.70 – < 0.90` ➔ Route: `queue_review`.
  - [x] `Confidence < 0.70` ➔ Route: `escalate`.
  - [x] **Mọi `HIGH_RISK_ACTIONS`** (chuyển tiền, đổi người nhận, đóng tài khoản) ➔ **bắt buộc Route: `escalate`** (Fail-closed). *(PASSED test_confidence_router_high_risk_always_escalates & thresholds)*
- [x] **TODO 12 (`hitl_decision_points`)**:
  - [x] Thiết kế 3 điểm duyệt (Decision Points) cho hành động nguy hiểm.
  - [x] Cung cấp đầy đủ thông tin context/diff (người nhận cũ/mới, số tiền) cho Reviewer.
  - [x] Đảm bảo xử lý chính xác 3 trạng thái: `Approve`, `Reject`, và `Timeout` (Không tự động gửi tiền khi hết giờ). *(PASSED test_hitl_points_include_reviewer_lifecycle)*

---

### 📍 Checkpoint 4 — Nhật ký Audit & Cảnh báo giám sát (Monitoring)
*Files thực hiện:* [`src/assignment/audit_log.py`](file:///Users/dauquocduy/workspace/AI20K/lab/Day11_2A202601445_DauQuocDuy/src/assignment/audit_log.py), [`src/assignment/monitoring.py`](file:///Users/dauquocduy/workspace/AI20K/lab/Day11_2A202601445_DauQuocDuy/src/assignment/monitoring.py), & [`src/assignment/rate_limiter.py`](file:///Users/dauquocduy/workspace/AI20K/lab/Day11_2A202601445_DauQuocDuy/src/assignment/rate_limiter.py)

- [x] **Audit Log (`AuditLogPlugin`)**:
  - [x] Sử dụng một `request_id` duy nhất nối từ input ➔ decision ➔ output.
  - [x] Ghi lại timestamp, layer phát hiện, latency và quyết định của reviewer.
  - [x] Lưu kết quả ra file `outputs/audit_log.json`. *(PASSED)*
- [x] **Rate Limiter (`RateLimiter`)**:
  - [x] Triển khai thuật toán Sliding Window giới hạn số request/phút. *(PASSED)*
- [x] **Monitoring & Alerts (`MonitoringAlert`)**:
  - [x] Đếm và tính toán tỷ lệ: Block Rate, Rate Limit Hits, Judge Failure Rate.
  - [x] Bật cảnh báo (Alert) khi chỉ số vượt ngưỡng cho phép.
  - [x] Xuất báo cáo ra `outputs/metrics.json`. *(PASSED)*

---

### 📍 Checkpoint 5 — Red Team (Tấn công mô phỏng) & Đánh giá an toàn
*Files thực hiện:* [`src/attacks/attacks.py`](file:///Users/dauquocduy/workspace/AI20K/lab/Day11_2A202601445_DauQuocDuy/src/attacks/attacks.py), [`src/testing/testing.py`](file:///Users/dauquocduy/workspace/AI20K/lab/Day11_2A202601445_DauQuocDuy/src/testing/testing.py), & [`src/main.py`](file:///Users/dauquocduy/workspace/AI20K/lab/Day11_2A202601445_DauQuocDuy/src/main.py)

- [x] **TODO 13 (`run_attacks` trong `attacks.py`)**:
  - [x] Viết 5 prompt tấn công độc hại thuộc 5 nhóm (Completion, Reformatting, Creative writing, Confirmation, Gradual escalation). *(PASSED)*
- [x] **TODO 14 (Tự động sinh testcase tấn công bằng AI)**:
  - [x] Sinh kịch bản tấn công qua `generate_ai_attacks()` dùng `gemini-3.1-flash-lite`. *(PASSED)*
- [x] **TODO 9 (`run_comparison` trong `testing.py`)**:
  - [x] Thử nghiệm so sánh hiệu quả Trước và Sau khi bật Guardrails (Before vs After). *(PASSED)*
- [x] **TODO 10 (`SecurityTestPipeline` trong `testing.py`)**:
  - [x] Tự động hóa đường ống kiểm thử an toàn, tính toán `block_rate` và `leak_rate`. *(PASSED)*

---

### 📍 Checkpoint 6 — Viết Báo cáo & Đóng gói nộp bài
*File thực hiện:* [`report/2A202601445_report.md`](file:///Users/dauquocduy/workspace/AI20K/lab/Day11_2A202601445_DauQuocDuy/report/2A202601445_report.md) & Root Folder

- [x] **Viết Báo cáo Red Team (`report/2A202601445_report.md`)**:
  - [x] Nguồn gốc câu lệnh tấn công (User / Email / RAG / Tool).
  - [x] Hậu quả nếu không bị chặn (Lộ secret, chuyển tiền trái phép, v.v.).
  - [x] Lớp bảo mật nào đã ngăn chặn được và cơ chế hoạt động.
  - [x] Phân tích điểm trade-off / bất tiện đối với người dùng cuối (nếu có).
  - [x] Chuỗi vết log/metric/alert chứng minh sự cố. *(COMPLETED)*
- [x] **Chạy Self-Check toàn bộ bài nộp**:
  - [x] `pytest tests/smoke -q` *(5/5 passed)*.
  - [x] `pytest tests/public -q` *(13/13 passed - 100%)*.
  - [x] `python scripts/grade.py --submission-dir . --out outputs/grade_report.json` *(technical_failure: false, schema points: 10/10)*.
- [x] **Kiểm tra Artifacts trước khi Commit**:
  - [x] Đảm bảo có đầy đủ: `README.md`, `src/assignment/`, `src/attacks/attacks.py`, `outputs/results.json`, `outputs/audit_log.json`, `outputs/metrics.json`, `outputs/attack_results.json`, `report/2A202601445_report.md`.
  - [x] **KHÔNG COMMIT** file `.env`, API key, token hoặc dữ liệu nhạy cảm thực tế.
- [x] **Nộp bài**: Push code lên repo GitHub Fork và gửi link trên Codelabs. *(Sẵn sàng nộp bài!)*
