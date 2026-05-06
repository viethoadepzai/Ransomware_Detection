# Kiến trúc dự án phát hiện mã độc Ryuk

Dự án này sử dụng kiến trúc pipeline học máy tiêu chuẩn:

1. **Thu thập dữ liệu**: Các mẫu mã độc Ryuk và file an toàn được tải xuống và lưu trong `data/raw/`. Thông tin được ghi vào `data/manifest.csv`.
2. **Tiền xử lý (Preprocessing)**: Làm sạch, giải nén (nếu cần), kiểm tra tính toàn vẹn của file.
3. **Trích xuất đặc trưng (Feature Extraction)**: Trích xuất các đặc trưng tĩnh (như thông tin header PE, sections, imports) hoặc kết quả phân tích động (system calls log, API traces).
4. **Huấn luyện mô hình (Training)**: Dữ liệu được chia thành train/test. Áp dụng các thuật toán như Random Forest, XGBoost hoặc Deep Learning để huấn luyện mô hình.
5. **Đánh giá (Evaluation)**: Sử dụng các metric như Accuracy, Precision, Recall, F1-Score, ROC-AUC để đánh giá khả năng nhận diện của mô hình.
6. **Triển khai (Deployment/CI)**: (Tùy chọn) Triển khai mô hình dưới dạng API hoặc tích hợp vào hệ thống EDR.
