# Dự án AI phát hiện mã độc Ryuk

Dự án này tập trung xây dựng giải pháp AI nhằm tự động phát hiện hoạt động mã độc Ryuk trên hệ thống (phân loại mẫu file hoặc hành vi là Ryuk hay không). 

## Mục tiêu
Phát hiện tĩnh/động ở mức cá nhân (endpoint).

## Cấu trúc thư mục
- `data/`: Chứa dữ liệu thô và đã xử lý.
- `src/`: Mã nguồn chính.
- `notebooks/`: Jupyter notebooks cho thăm dò dữ liệu.
- `models/`: Lưu trữ mô hình huấn luyện.
- `logs/`: Ghi nhận nhật ký huấn luyện.
- `config/`: Cấu hình hệ thống.
- `docs/`: Tài liệu dự án.
- `tests/`: Kịch bản kiểm thử.

## Cách cài đặt

1. Clone kho lưu trữ:
```bash
git clone <repository_url>
cd ransomeware
```

2. Tạo môi trường ảo và cài đặt thư viện:
```bash
python -m venv venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```
