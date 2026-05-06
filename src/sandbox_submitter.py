import requests
import time
import json
import joblib
import numpy as np
import os
import logging
from src.features import extract_static_features, extract_dynamic_features

# Thiết lập Logger chuyên nghiệp cho đồng bộ với repo
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ==========================================
# CẤU HÌNH HỆ THỐNG
# ==========================================
# Đổi thành "https://capesandbox.com" nếu bạn dùng Sandbox Online, 
# và nhớ thêm Headers chứa API_KEY vào các request nhé!
CAPE_URL = "http://localhost:8000"
MODEL_PATH = "models/ryuk_xgboost_model.joblib"
FEATURE_LIST_PATH = "models/features_list.json"

# ===============================
# 1. Submit file lên CAPE
# ===============================
def submit_file(file_path):
    url = f"{CAPE_URL}/apiv2/tasks/create/file/"
    if not os.path.exists(file_path):
        logger.error(f"File không tồn tại: {file_path}")
        return None

    logger.info(f"Đang đẩy file {file_path} lên hệ thống CAPE Sandbox...")
    try:
        with open(file_path, "rb") as f:
            files = {"file": f}
            r = requests.post(url, files=files)
            r.raise_for_status()
            
        task_id = r.json().get("task_id")
        if not task_id:
            logger.error(f"Lỗi phản hồi từ CAPE: {r.text}")
            return None
            
        logger.info(f"Upload thành công! Task ID của bạn là: {task_id}")
        return task_id
    except Exception as e:
        logger.error(f"Lỗi khi upload file: {e}")
        return None

# ===============================
# 2. Đợi sandbox chạy xong
# ===============================
def wait_for_task(task_id):
    url = f"{CAPE_URL}/apiv2/tasks/view/{task_id}"
    logger.info("Đang chờ máy ảo khởi động và phân tích (có thể mất vài phút)...")
    
    while True:
        try:
            r = requests.get(url)
            status = r.json().get("task", {}).get("status", "unknown")
            
            logger.info(f"  Trạng thái hiện tại: {status}")
            
            if status == "reported":
                logger.info("Phân tích hoàn tất! Chuẩn bị trích xuất báo cáo.")
                break
            elif status in ["failed", "deleted"]:
                logger.error("Quá trình Sandbox bị lỗi hoặc bị hủy!")
                return False
                
            time.sleep(5)
        except Exception as e:
            logger.error(f"Mất kết nối với CAPE: {e}")
            time.sleep(5)
            
    return True

# ===============================
# 3. Lấy report JSON
# ===============================
def get_report(task_id):
    url = f"{CAPE_URL}/apiv2/tasks/report/{task_id}/json"
    logger.info("Đang tải file báo cáo JSON hành vi về máy...")
    
    try:
        r = requests.get(url)
        r.raise_for_status()
        
        # Lưu vào thư mục test để tiện theo dõi
        report_path = os.path.join("data", f"sandbox_report_{task_id}.json")
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(r.json(), f, indent=4)
            
        logger.info(f"Đã lưu thành công báo cáo tại: {report_path}")
        return report_path
    except Exception as e:
        logger.error(f"Lỗi tải report: {e}")
        return None

# ===============================
# 4. Predict
# ===============================
def predict(file_path, json_path):
    logger.info("Đang trích xuất đặc trưng (Features Extraction)...")
    
    # Lấy cả 2 loại đặc trưng Tĩnh & Động
    static_feat = extract_static_features(file_path)
    dynamic_feat = extract_dynamic_features(json_path)
    
    # Gộp toàn bộ vào một từ điển chung
    features = {**static_feat, **dynamic_feat}
    
    # QUAN TRỌNG: Bật cờ báo hiệu đã có dữ liệu động
    features['dyn_has_dynamic'] = 1
    
    # Load danh sách cột đồng bộ
    try:
        with open(FEATURE_LIST_PATH, "r") as f:
            feature_order = json.load(f)
    except FileNotFoundError:
        logger.error("Không tìm thấy features_list.json. Vui lòng chạy py -m src.train trước.")
        return

    # Sắp xếp đúng mảng features
    X = np.array([features.get(f, 0.0) for f in feature_order]).reshape(1, -1)
    
    # Load model
    if not os.path.exists(MODEL_PATH):
        logger.error("Không tìm thấy Model AI. Vui lòng chạy py -m src.train trước.")
        return
        
    model = joblib.load(MODEL_PATH)
    
    # Dự đoán (Xác suất độc hại)
    prob = model.predict_proba(X)[0][1]
    
    print("\n" + "="*40)
    print(" KẾT QUẢ QUÉT AI (FULL PIPELINE)")
    print("="*40)
    print(f"File thực thi: {os.path.basename(file_path)}")
    print(f"Xác suất độc hại: {prob*100:.2f}%")
    
    if prob > 0.7:
        print("=> 🚨 RỦI RO CỰC CAO (Ransomware-like)")
    elif prob > 0.4:
        print("=> ⚠️ ĐÁNG NGỜ (Suspicious)")
    else:
        print("=> ✅ AN TOÀN (Clean)")
    print("="*40)

# ===============================
# MAIN PIPELINE
# ===============================
def scan(file_path):
    task_id = submit_file(file_path)
    if not task_id: return
    
    success = wait_for_task(task_id)
    if not success: return
    
    json_path = get_report(task_id)
    if not json_path: return
    
    predict(file_path, json_path)

if __name__ == "__main__":
    print("=== CÔNG CỤ TÍCH HỢP CAPE SANDBOX ===")
    exe_path = input("Nhập đường dẫn tuyệt đối đến file .exe: ").strip()
    
    # Fix lỗi nháy kép khi kéo thả file vào terminal
    if exe_path.startswith('"') and exe_path.endswith('"'):
        exe_path = exe_path[1:-1]
        
    if os.path.exists(exe_path):
        scan(exe_path)
    else:
        print("Lỗi: Không tìm thấy file ở đường dẫn trên!")
