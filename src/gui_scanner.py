import os
import json
import joblib
import pandas as pd
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.features import extract_static_features, extract_dynamic_features
from src.utils import setup_logger

logger = setup_logger('gui', 'logs/gui.log')

class RansomwareScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ryuk Ransomware AI Scanner (Research Level)")
        self.root.geometry("600x450")
        self.root.resizable(False, False)
        
        # Cấu hình giao diện cơ bản
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Biến lưu trữ
        self.model = None
        self.feature_cols = None
        
        self._load_model()
        self._build_ui()
        
    def _load_model(self):
        try:
            model_path = 'models/ryuk_xgboost_model.joblib'
            features_path = 'models/features_list.json'
            
            if not os.path.exists(model_path) or not os.path.exists(features_path):
                messagebox.showwarning("Thiếu Model", "Chưa tìm thấy Model đã train. Vui lòng chạy 'py -m src.train' trước khi mở GUI.")
                self.root.destroy()
                return
                
            self.model = joblib.load(model_path)
            with open(features_path, 'r') as f:
                self.feature_cols = json.load(f)
            logger.info("Đã tải Model và Features List thành công.")
        except Exception as e:
            logger.error(f"Lỗi tải model: {e}")
            messagebox.showerror("Lỗi", f"Lỗi khởi tạo hệ thống: {str(e)}")
            self.root.destroy()

    def _build_ui(self):
        # Tiêu đề
        title_frame = tk.Frame(self.root, bg="#2c3e50")
        title_frame.pack(fill=tk.X)
        
        lbl_title = tk.Label(title_frame, text="RANSOMWARE DETECTOR", fg="white", bg="#2c3e50", font=("Helvetica", 16, "bold"))
        lbl_title.pack(pady=10)
        
        # Phần chọn file
        select_frame = tk.Frame(self.root)
        select_frame.pack(pady=20)
        
        lbl_instruction = tk.Label(select_frame, text="Chọn loại file để quét:", font=("Helvetica", 11))
        lbl_instruction.pack(pady=5)
        
        btn_frame = tk.Frame(select_frame)
        btn_frame.pack()
        
        btn_scan_exe = tk.Button(btn_frame, text="📁 Quét File Thực thi (.exe)", width=25, height=2, bg="#3498db", fg="white", font=("Helvetica", 10, "bold"), command=self._scan_exe)
        btn_scan_exe.grid(row=0, column=0, padx=10)
        
        btn_scan_log = tk.Button(btn_frame, text="📄 Quét File Báo Cáo (.json)", width=25, height=2, bg="#e67e22", fg="white", font=("Helvetica", 10, "bold"), command=self._scan_json)
        btn_scan_log.grid(row=0, column=1, padx=10)
        
        # Phần hiển thị kết quả
        self.result_frame = tk.Frame(self.root, bd=2, relief="groove")
        self.result_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.lbl_status = tk.Label(self.result_frame, text="Hệ thống Sẵn sàng...", font=("Helvetica", 12))
        self.lbl_status.pack(pady=10)
        
        self.lbl_score = tk.Label(self.result_frame, text="", font=("Helvetica", 18, "bold"))
        self.lbl_score.pack(pady=5)
        
        self.txt_details = tk.Text(self.result_frame, height=8, width=60, font=("Consolas", 9), state=tk.DISABLED)
        self.txt_details.pack(pady=10)
        
    def _display_result(self, probability, features_dict, file_type):
        is_malicious = probability > 0.5
        
        if is_malicious:
            status_text = "⚠️ PHÁT HIỆN RANSOMWARE (RYUK)!"
            color = "#c0392b"
        else:
            status_text = "✅ FILE AN TOÀN"
            color = "#27ae60"
            
        self.lbl_status.config(text=status_text, fg=color)
        self.lbl_score.config(text=f"Xác suất độc hại: {probability*100:.1f}%", fg=color)
        
        self.txt_details.config(state=tk.NORMAL)
        self.txt_details.delete("1.0", tk.END)
        self.txt_details.insert(tk.END, f"Chế độ quét: {file_type}\n")
        self.txt_details.insert(tk.END, "-"*50 + "\n")
        self.txt_details.insert(tk.END, f"Entropy toàn cục: {features_dict.get('static_global_entropy', 0):.2f}\n")
        self.txt_details.insert(tk.END, f"Entropy lõi (Max Section): {features_dict.get('static_max_section_entropy', 0):.2f}\n")
        overlay_str = "Có (Cảnh báo lẩn tránh!)" if features_dict.get('static_has_overlay', 0) == 1 else "Không"
        self.txt_details.insert(tk.END, f"Dữ liệu thừa (Overlay): {overlay_str}\n")
        
        if features_dict.get('dyn_has_dynamic', 0) == 1:
            self.txt_details.insert(tk.END, f"Điểm Burst (Ghi file): {features_dict.get('dyn_write_burst_score', 0):.2f} ops/sec\n")
            self.txt_details.insert(tk.END, f"Đuôi file khả nghi (.RYK,...): {features_dict.get('dyn_suspicious_extension_count', 0)}\n")
            self.txt_details.insert(tk.END, f"Số lệnh cấm khôi phục: {features_dict.get('dyn_anti_recovery_cmds_count', 0)}\n")
        else:
            self.txt_details.insert(tk.END, "(Chỉ áp dụng các đặc trưng tĩnh - độ chính xác có thể giảm)\n")
            
        self.txt_details.config(state=tk.DISABLED)

    def _predict(self, features_dict, file_type):
        try:
            # Tạo DataFrame 1 dòng với các cột đúng như lúc train
            df = pd.DataFrame([features_dict])
            
            # Gán giá trị 0 cho các cột bị thiếu (nếu có)
            for col in self.feature_cols:
                if col not in df.columns:
                    df[col] = 0.0
                    
            # Sắp xếp đúng thứ tự
            df = df[self.feature_cols]
            
            # Dự đoán
            X = df.values
            prob = self.model.predict_proba(X)[0][1] # Xác suất nhãn 1 (Malicious)
            
            self._display_result(prob, features_dict, file_type)
            
        except Exception as e:
            logger.error(f"Lỗi dự đoán: {e}")
            messagebox.showerror("Lỗi", "Đã xảy ra lỗi trong quá trình dự đoán AI.")

    def _scan_exe(self):
        filepath = filedialog.askopenfilename(title="Chọn file thực thi (.exe)", filetypes=[("Executable Files", "*.exe"), ("All Files", "*.*")])
        if not filepath: return
        
        self.lbl_status.config(text="Đang phân tích tĩnh...", fg="black")
        self.root.update()
        
        features = extract_static_features(filepath)
        features['dyn_has_dynamic'] = 0 # Quan trọng: Cờ Missing Features
        
        self._predict(features, "Quét Nhanh (Static)")

    def _scan_json(self):
        filepath = filedialog.askopenfilename(title="Chọn file log JSON của Cuckoo Sandbox", filetypes=[("JSON Logs", "*.json")])
        if not filepath: return
        
        self.lbl_status.config(text="Đang phân tích hành vi...", fg="black")
        self.root.update()
        
        # Ở môi trường thực tế, nếu chọn log JSON, ta có thể không có file tĩnh.
        # Ở đây giả sử không có tĩnh, gán 0 cho tĩnh, và extract động.
        features = extract_dynamic_features(filepath)
        features['dyn_has_dynamic'] = 1
        
        # Nếu chưa có static, ta tự động gắn bằng 0
        static_keys = ['static_global_entropy', 'static_max_section_entropy', 'static_has_overlay', 
                       'static_suspicious_timestamp', 'static_rwx_sections', 'static_empty_iat',
                       'static_crypto_api_count', 'static_file_api_count', 'static_network_api_count', 
                       'static_registry_api_count', 'static_suspicious_dlls', 'static_number_of_sections']
        for k in static_keys:
            if k not in features: features[k] = 0.0
            
        self._predict(features, "Quét Sâu (Dynamic)")

if __name__ == "__main__":
    root = tk.Tk()
    app = RansomwareScannerGUI(root)
    root.mainloop()
