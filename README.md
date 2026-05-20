# 🔬 AI Encryption Detector - Fusion EDR Engine (FINAL V11)

Dự án nghiên cứu cấp độ chuyên gia (Research-Grade) ứng dụng Trí tuệ nhân tạo (AI) để **phát hiện và phân loại thuật toán mã hóa** do các dòng ransomware hiện đại gây ra. Thay vì chỉ phát hiện dựa trên chữ ký (signature) truyền thống, hệ thống sử dụng **Kiến trúc Fusion EDR 4 Giai đoạn** đi sâu vào cấu trúc tệp tin (block-level), phân tích ngữ nghĩa (semantic integrity) và hành vi entropy để nhận diện chính xác thuật toán mã hóa cũng như các thủ đoạn mã hóa lai (Hybrid Encryption) tinh vi nhất.

---

## 🌟 Kiến trúc Enterprise Research (4 Giai đoạn)

Hệ thống hoạt động dựa trên một Pipeline phát hiện 4 lớp (4-Stage Pipeline), loại bỏ hoàn toàn các trường hợp dương tính giả (False Positives) đối với các file nén hợp lệ (ZIP, PDF, PNG):

1. **Stage 1: Whole-file AI Behavioral Detector**
   - Quét toàn bộ file để trích xuất nhanh 16 đặc trưng thống kê.
   - Sử dụng mô hình nhị phân (Binary Model: XGBoost/RandomForest) để phân loại thô: *An toàn vs. Nghi ngờ bị mã hóa*.

2. **Stage 2: Sliding-window Crypto Behavior Analysis**
   - Phân tích sâu mức block (Block-level analysis) bằng kỹ thuật Sliding-window (cửa sổ trượt).
   - Tự động điều chỉnh kích thước block (Adaptive Analysis): 512 bytes cho file nhỏ, 2048/4096 bytes cho file lớn.
   - Nhận diện đa lớp (Multi-class Identification) để xác định thuật toán: *AES-CBC, AES-ECB, ChaCha20, RC4, 3DES, DES*.

3. **Stage 3: Evidence Fusion Engine (Động cơ tổng hợp bằng chứng)**
   - Kết hợp các trọng số rủi ro để đưa ra quyết định cuối cùng:
     - `W_AI (0.35)`: Điểm số từ mô hình Machine Learning.
     - `W_BEHAVIOR (0.30)`: Điểm hành vi mã hóa (Entropy Behavior).
     - `W_STRUCTURAL (0.20)`: Điểm phá hoại cấu trúc (Structural Damage).
     - `W_ANOMALY (0.05)`: Điểm bất thường ngữ nghĩa (Semantic Anomaly).
     - `W_SURVIVABILITY (0.40)`: Đánh giá khả năng khôi phục của tệp.

4. **Stage 4: Explainable EDR Decision Layer (Lớp giải thích quyết định)**
   - Đưa ra kết luận minh bạch qua tính năng Explainable AI (XAI), cung cấp báo cáo chi tiết về lý do file bị đánh dấu là mã độc.

---

## 🧠 Phân tích Hành vi Ransomware (Behavioral Profiling)

Hệ thống có khả năng nhận diện 7 lớp hành vi mã hóa (Behavior Classes) xuất hiện trong các chiến dịch tấn công thực tế:

- **Uniform Encryption**: Mã hóa toàn bộ đồng nhất (VD: *WannaCry, Conti*).
- **Intermittent Encryption**: Mã hóa ngắt quãng để tăng tốc độ (VD: *LockBit 3.0, BlackCat*).
- **Partial Encryption**: Chỉ mã hóa một phần file (VD: *Ryuk, Play*).
- **Header/Footer Tampering**: Ghi đè/Phá hủy Header hoặc Footer (VD: *Phobos*).
- **Pattern Leakage (Weak Crypto)**: Rò rỉ pattern do sử dụng thuật toán mã hóa yếu (VD: AES-ECB, XOR).
- **Obfuscation**: Làm rối mã, entropy không đồng đều.
- **Safe Compressed Content**: Phân biệt chính xác giữa mã hóa và nén hợp lệ (GZIP, ZIP, PDF).

---

## 🔬 Trích xuất đặc trưng (Feature Engineering - FINAL V10)

Lõi thuật toán `crypto_features.py` trích xuất các nhóm đặc trưng toán học và cấu trúc sau:

### 1. Phân tích Entropy và Thống kê (Entropy & Byte Statistics)
- **Shannon Entropy**: Đo lường sự hỗn loạn của dữ liệu (mã hóa ≈ 8.0).
- **Entropy Gradient & Transition**: Tính toán Mean, Std, Delta, đếm số lượng "cú sốc Entropy" (Entropy Shock Score) và số lần "Spike".
- **Chi-square Test & Serial Correlation**: Kiểm tra độ đồng đều phân phối byte và tương quan nối tiếp.
- **Hình thái phân bố**: Mean, Median, Variance, Skewness, Kurtosis.

### 2. Phân tích tính toàn vẹn cấu trúc (Structural Integrity - V12 Optimized)
- Kiểm tra tính hợp lệ của Header/Footer đặc trưng của định dạng file gốc.
- **Image Integrity**: Phân tích IHDR/IDAT, Pixel Stream Decoding (bắt lỗi crash nếu file bị mã hóa một phần).
- **PDF/ZIP Integrity**: Kiểm tra sự tồn tại của `%%EOF`, Magic headers (`PK`), và kiểm tra thử cấu trúc XML lõi bên trong tài liệu Office (`word/document.xml`, `xl/workbook.xml`).

---

## 📂 Cấu trúc thư mục hệ thống

```text
├── config/
│   └── config.yaml                 # Tham số mô hình, danh sách cipher (AES, RC4...)
├── data/
│   ├── processed/                  # Feature matrix cho huấn luyện
│   └── ransomware_dataset/         # Dữ liệu mô phỏng Hybrid Ransomware
├── src/
│   ├── generate_challenge_dataset.py # Trình sinh dataset Research-Grade V2 (Mô phỏng LockBit, Ryuk, v.v)
│   ├── build_crypto_dataset.py     # Trích xuất đặc trưng & xây dựng Feature Matrix
│   ├── crypto_features.py          # Lõi tính toán tính vẹn toàn, semantic & entropy
│   ├── train_crypto.py             # Pipeline huấn luyện Two-Stage AI (XGBoost/RF)
│   ├── detect_encryption.py        # EDR Engine 4-Stage, xử lý mmap an toàn bộ nhớ
│   ├── gui.py                      # Giao diện XAI Dashboard Enterprise (Dual Entropy Graph)
│   └── utils.py                    # Logging, Utilities
├── models/
│   ├── stage1_binary.joblib        # Trọng số mô hình Giai đoạn 1
│   ├── stage2_multiclass.joblib    # Trọng số mô hình Giai đoạn 2
│   ├── stage2_label_encoder.joblib # Trình mã hóa nhãn
│   └── model_metadata.json         # Danh sách tính năng (cols_s1, cols_s2)
├── logs/                           # Log hệ thống, XAI SHAP plots
├── README.md
└── requirements.txt
```

---

## 🚀 Hướng dẫn cài đặt

**1. Clone kho lưu trữ:**
```bash
git clone <repository_url>
cd ransomeware
```

**2. Tạo môi trường ảo và cài đặt thư viện:**
```bash
python -m venv .venv
# Trên Windows:
.\.venv\Scripts\activate
# Trên Linux/Mac:
# source .venv/bin/activate

pip install -r requirements.txt
```

---

## 💻 Hướng dẫn sử dụng

### 1. Khởi động Giao diện người dùng (Enterprise XAI GUI)
Dashboard tích hợp Biểu đồ Dual Entropy, phân tích rủi ro chi tiết (Risk Breakdown Panel) và hỗ trợ Scan Thư mục đa luồng.
```bash
python -m src.gui
```

### 2. Sinh dữ liệu mô phỏng (Hybrid Ransomware Dataset)
Sử dụng công cụ sinh dữ liệu để tạo ra các kịch bản mã hóa đa thuật toán, ngắt quãng giống hệt Ransomware đời thực.
```bash
python -m src.generate_challenge_dataset
```

### 3. Huấn luyện mô hình Two-Stage AI
Trích xuất lại cấu trúc đặc trưng mới và train hệ thống phân loại.
```bash
# Trích xuất dữ liệu, xây ma trận
python -m src.build_crypto_dataset

# Bắt đầu quá trình Train Pipeline
python -m src.train_crypto --config config/config.yaml
```

### 4. Phát hiện qua Command Line (CLI Integration)
Sử dụng cho hệ thống backend hoặc tích hợp vào hệ thống phản ứng tự động (SOAR/SIEM).
```bash
# Quét kiểm tra 1 tệp tin
python -m src.detect_encryption --file "path/to/suspicious_file.enc"

# Ép hệ thống dùng Block-level analysis chuyên sâu
python -m src.detect_encryption --blocks "path/to/suspicious_file.enc"

# Quét đệ quy toàn bộ thư mục
python -m src.detect_encryption --dir "path/to/directory"
```

---

## 📚 Tài liệu & Nghiên cứu tham khảo
- **Hybrid Encryption & Tactic Leakage**: *LockBit 3.0 & BlackCat Ransomware Intermittent Encryption Analysis*.
- **Machine Learning for Forensics**: *Encryption Algorithm Classification from Ciphertext*.
- **XAI in Cybersecurity**: *SHAP (SHapley Additive exPlanations) for Model Interpretability*.
