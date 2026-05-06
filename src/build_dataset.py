import os
import pandas as pd
import numpy as np
import random
from src.utils import setup_logger, ensure_dir

logger = setup_logger('build_dataset', 'logs/build_dataset.log')

def generate_realistic_dataset(num_samples=1000, output_path='data/processed/features_matrix.csv'):
    """
    Sinh ra tập dataset giả lập theo phân phối HỢP LÝ với thực tế sandbox.

    Các giá trị đã được hiệu chỉnh dựa trên phân tích báo cáo CAPE Sandbox thực tế:
    - Một sandbox session thường chỉ kéo dài 60-300 giây
    - Ryuk mã hóa được 5-500 file trong thời gian giới hạn đó
    - burst_score = file_ops / duration → ở sandbox = 0.01 - 5.0 ops/sec (không phải hàng nghìn)
    - unique_dirs: Ryuk thực tế thường động đến 2-50 thư mục trong session ngắn
    """
    logger.info(f"Bắt đầu sinh giả lập {num_samples} dòng dữ liệu (REAL-SCALE distribution)...")

    data = []

    for i in range(num_samples):
        # 40% malware
        label = 1 if random.random() < 0.4 else 0

        # ── Static Features ────────────────────────────────────────────────────
        has_static = 1 if random.random() < 0.8 else 0

        if has_static == 0:
            static_global_entropy         = 0.0
            static_max_section_entropy    = 0.0
            static_has_overlay            = 0
            static_suspicious_timestamp   = 0
            static_rwx_sections           = 0
            static_empty_iat              = 0
            static_total_imports          = 0
            static_dll_count              = 0
            static_api_ratio              = 0.0
            static_crypto_api_count       = 0
            static_file_api_count         = 0
            static_network_api_count      = 0
            static_registry_api_count     = 0
            static_suspicious_dlls        = 0
            static_number_of_sections     = 0
        else:
            if label == 1:
                # =============================================================
                # RYUK (Packed malware): các gia trị sát thực tế quan sát được
                # =============================================================
                # Entropy cao (file bị nén): 5.8 – 7.99
                static_global_entropy         = np.random.uniform(5.8, 7.99)
                static_max_section_entropy    = np.random.uniform(6.0, 7.99)
                static_has_overlay            = 1 if random.random() < 0.5 else 0
                static_suspicious_timestamp   = 1 if random.random() < 0.3 else 0
                static_rwx_sections           = np.random.randint(0, 3)
                static_empty_iat              = 0  # packer stub vẫn có import

                # Import table của stub: 50 – 130 entries
                static_total_imports          = np.random.randint(50, 130)

                # Packer stub gọi một số API cơ bản — ít hơn benign rất nhiều
                static_crypto_api_count       = 0 if random.random() < 0.8 else np.random.randint(1, 8)
                # Stub gọi một ít API file (CloseHandle, ReadFile, CreateFileW...)
                static_file_api_count         = np.random.randint(0, 15)
                static_network_api_count      = np.random.randint(0, 5)
                static_registry_api_count     = np.random.randint(0, 5)
                # 60% packed stub không dùng crypt DLL
                static_suspicious_dlls        = 0 if random.random() < 0.6 else np.random.randint(1, 3)
                static_number_of_sections     = np.random.randint(3, 8)

                # Ryuk packed stub: chỉ import từ 1-5 DLL (kernel32, ntdll, ...)
                static_dll_count              = np.random.randint(1, 6)

                # API ratio cực kỳ thấp: named_api / total_imports ≈ 0 – 8%
                named_apis = static_file_api_count + static_network_api_count + static_registry_api_count + static_crypto_api_count
                static_api_ratio              = named_apis / max(static_total_imports, 1)

            else:
                # =============================================================
                # BENIGN: mô phỏng 2 loại phần mềm thực tế
                # =============================================================
                # Loại 1: small/system (40%) – notepad, calc, etc.
                # Loại 2: large/complex (60%) – Chrome, Office, etc.
                is_large_app = random.random() < 0.6

                if is_large_app:
                    # Large app: entropy có thể cao do compress nội bộ
                    # NHƯĖNG import rất nhiều và đa dạng hơn Ryuk rất nhiều
                    static_global_entropy         = np.random.uniform(4.5, 7.5)
                    static_max_section_entropy    = np.random.uniform(5.0, 7.5)
                    static_has_overlay            = 1 if random.random() < 0.15 else 0
                    static_suspicious_timestamp   = 0
                    static_rwx_sections           = 0
                    static_empty_iat              = 0

                    # Large app: rất nhiều imports (200 – 700), API đa dạng
                    static_total_imports          = np.random.randint(200, 700)
                    # Chúng có rất nhiều API match với danh sách mở rộng của chúng ta
                    static_file_api_count         = np.random.randint(50, 200)
                    static_network_api_count      = np.random.randint(10, 60)
                    static_registry_api_count     = np.random.randint(10, 50)
                    static_crypto_api_count       = np.random.randint(0, 5)
                    static_suspicious_dlls        = 0
                    static_number_of_sections     = np.random.randint(4, 15)
                    # Large app: import từ nhiều DLL (10-60) — khác biệt hẳn Ryuk
                    static_dll_count              = np.random.randint(10, 60)

                    named_apis = static_file_api_count + static_network_api_count + static_registry_api_count + static_crypto_api_count
                    # API ratio cao: 15 – 60%
                    static_api_ratio              = named_apis / max(static_total_imports, 1)

                else:
                    # Small/system app: import vừa phải
                    # NOTE: notepad có 50 DLL, entropy 6.48 — phải bỏ phủ range này
                    static_global_entropy         = np.random.uniform(3.5, 7.0)
                    static_max_section_entropy    = np.random.uniform(4.0, 7.0)
                    static_has_overlay            = 1 if random.random() < 0.05 else 0
                    static_suspicious_timestamp   = 0
                    static_rwx_sections           = 0
                    static_empty_iat              = 0

                    # Small app: imports vừa phải (20 – 350)
                    static_total_imports          = np.random.randint(20, 350)
                    # notepad=29 file_api, cần bảo đảm training bủ phủ range này
                    static_file_api_count         = np.random.randint(15, 80)
                    static_network_api_count      = np.random.randint(0, 20)
                    static_registry_api_count     = np.random.randint(0, 20)
                    static_crypto_api_count       = np.random.randint(0, 3)
                    static_suspicious_dlls        = 0
                    static_number_of_sections     = np.random.randint(3, 10)
                    # Small/system app: 5-55 DLL (notepad=50, cụngă rộng cho mọi loại system app)
                    static_dll_count              = np.random.randint(5, 55)

                    named_apis = static_file_api_count + static_network_api_count + static_registry_api_count + static_crypto_api_count
                    # API ratio trung bình: 5 – 50%
                    static_api_ratio              = named_apis / max(static_total_imports, 1)


        # ── Dynamic Features ───────────────────────────────────────────────────
        # 30% mẫu không có log động (sandbox timeout, file từ chối chạy, v.v.)
        has_dynamic = 1 if random.random() < 0.7 else 0

        if has_dynamic == 0:
            dyn_features = {
                "dyn_file_write_count": 0,        "dyn_file_rename_count": 0,
                "dyn_suspicious_extension_count": 0, "dyn_anti_recovery_cmds_count": 0,
                "dyn_registry_modified_count": 0,  "dyn_rename_ratio": 0.0,
                "dyn_suspicious_ext_ratio": 0.0,   "dyn_crypto_api_ratio": 0.0,
                "dyn_file_api_ratio": 0.0,         "dyn_dirs_ratio": 0.0,
                "dyn_has_dynamic": 0,              "dyn_write_burst_score": 0.0,
                "dyn_unique_dirs_touched": 0,      "dyn_file_type_diversity": 0,
            }
        else:
            if label == 1:
                # ── Ryuk: REAL-SCALE (bám sát báo cáo CAPE thực tế) ──────────
                # Sandbox session: có thể rất ngắn (2s) hoặc dài (300s)
                # Tạo cả 2 trường hợp để model học đủ phổ
                sandbox_duration = np.random.choice([
                    np.random.uniform(2, 10),    # 20%: session rất ngắn → burst cao
                    np.random.uniform(60, 300)   # 80%: session bình thường
                ], p=[0.2, 0.8])
                write_count  = np.random.randint(10, 500)
                rename_count = int(write_count * np.random.uniform(0.5, 1.0))
                total_ops    = write_count + rename_count

                suspicious_ext_count = int(total_ops * np.random.uniform(0.6, 1.0))

                dyn_file_write_count           = write_count
                dyn_file_rename_count          = rename_count
                dyn_suspicious_extension_count = suspicious_ext_count
                dyn_anti_recovery_cmds_count   = np.random.randint(1, 6)
                dyn_registry_modified_count    = np.random.randint(1, 10)

                dyn_rename_ratio         = rename_count / max(total_ops, 1)
                dyn_suspicious_ext_ratio = suspicious_ext_count / max(total_ops, 1)
                # Crypto API = 5-50% total calls (Ryuk dùng nhiều Crypt*)
                dyn_crypto_api_ratio     = np.random.uniform(0.05, 0.50)
                # File API = 20-60% total calls
                dyn_file_api_ratio       = np.random.uniform(0.20, 0.60)
                # Dirs: Ryuk lan rộng 1-50 thư mục
                dyn_unique_dirs_touched  = np.random.randint(1, 50)
                dyn_dirs_ratio           = dyn_unique_dirs_touched / max(total_ops, 1)
                dyn_has_dynamic          = 1
                # Burst = ops / duration: 0.01 - rất cao (khi duration ngắn)
                dyn_write_burst_score    = total_ops / sandbox_duration
                # File type: thường 1-10 loại (.docx, .xlsx, .pdf, .jpg, ...)
                dyn_file_type_diversity  = np.random.randint(1, 12)
            else:
                # ── Benign: normal process hoạt động bình thường ───────────────
                dyn_file_write_count           = np.random.randint(0, 30)
                dyn_file_rename_count          = np.random.randint(0, 5)
                dyn_suspicious_extension_count = 0
                dyn_anti_recovery_cmds_count   = 0
                dyn_registry_modified_count    = np.random.randint(0, 5)
                dyn_rename_ratio               = np.random.uniform(0.0, 0.2)
                dyn_suspicious_ext_ratio       = 0.0
                dyn_crypto_api_ratio           = np.random.uniform(0.0, 0.03)
                dyn_file_api_ratio             = np.random.uniform(0.05, 0.30)
                dyn_unique_dirs_touched        = np.random.randint(1, 5)
                total_ops_benign               = dyn_file_write_count + dyn_file_rename_count
                dyn_dirs_ratio                 = dyn_unique_dirs_touched / max(total_ops_benign, 1)
                dyn_has_dynamic                = 1
                # Benign: burst rất thấp (0.0 - 1.0 ops/sec)
                dyn_write_burst_score          = np.random.uniform(0.0, 1.0)
                dyn_file_type_diversity        = np.random.randint(1, 4)

            dyn_features = {
                "dyn_file_write_count":          dyn_file_write_count,
                "dyn_file_rename_count":         dyn_file_rename_count,
                "dyn_suspicious_extension_count": dyn_suspicious_extension_count,
                "dyn_anti_recovery_cmds_count":  dyn_anti_recovery_cmds_count,
                "dyn_registry_modified_count":   dyn_registry_modified_count,
                "dyn_rename_ratio":              dyn_rename_ratio,
                "dyn_suspicious_ext_ratio":      dyn_suspicious_ext_ratio,
                "dyn_crypto_api_ratio":          dyn_crypto_api_ratio,
                "dyn_file_api_ratio":            dyn_file_api_ratio,
                "dyn_dirs_ratio":                dyn_dirs_ratio,
                "dyn_has_dynamic":               dyn_has_dynamic,
                "dyn_write_burst_score":         dyn_write_burst_score,
                "dyn_unique_dirs_touched":       dyn_unique_dirs_touched,
                "dyn_file_type_diversity":       dyn_file_type_diversity,
            }

        row = {
            "sample_id":                    i,
            "file_name":                    f"sample_{i}.exe",
            "label_encoded":                label,
            "static_global_entropy":        static_global_entropy,
            "static_max_section_entropy":   static_max_section_entropy,
            "static_has_overlay":           static_has_overlay,
            "static_suspicious_timestamp":  static_suspicious_timestamp,
            "static_rwx_sections":          static_rwx_sections,
            "static_empty_iat":             static_empty_iat,
            "static_total_imports":         static_total_imports if has_static else 0,
            "static_dll_count":             static_dll_count if has_static else 0,
            "static_api_ratio":             static_api_ratio if has_static else 0.0,
            "static_crypto_api_count":      static_crypto_api_count,
            "static_file_api_count":        static_file_api_count,
            "static_network_api_count":     static_network_api_count,
            "static_registry_api_count":    static_registry_api_count,
            "static_suspicious_dlls":       static_suspicious_dlls,
            "static_number_of_sections":    static_number_of_sections,
        }
        row.update(dyn_features)
        data.append(row)

    df = pd.DataFrame(data)
    ensure_dir(os.path.dirname(output_path))
    df.to_csv(output_path, index=False)
    logger.info(f"Đã tạo file {output_path} với {len(df)} dòng (REAL-SCALE distribution).")

if __name__ == "__main__":
    generate_realistic_dataset()
