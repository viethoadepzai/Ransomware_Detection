import os
import pandas as pd
import numpy as np
import logging
from src.utils import setup_logger, ensure_dir

# Khởi tạo logger cho module
logger = setup_logger('preprocessing', 'logs/preprocessing.log')

def load_data(manifest_path):
    """
    Tải dữ liệu từ manifest.csv.
    
    Args:
        manifest_path (str): Đường dẫn tới file manifest.
        
    Returns:
        pd.DataFrame: DataFrame chứa thông tin dữ liệu.
    """
    logger.info(f"Bắt đầu tải manifest từ: {manifest_path}")
    try:
        df = pd.read_csv(manifest_path)
        logger.info(f"Đã tải thành công {len(df)} bản ghi.")
        return df
    except FileNotFoundError:
        logger.error(f"Không tìm thấy file: {manifest_path}")
        raise
    except Exception as e:
        logger.error(f"Lỗi khi đọc file manifest: {e}")
        raise

def handle_missing_values(df):
    """Xử lý các giá trị NaN/Null trong dữ liệu."""
    logger.info("Kiểm tra và xử lý dữ liệu thiếu (missing values)...")
    
    # Kiểm tra số lượng missing values
    missing_counts = df.isnull().sum()
    if missing_counts.sum() > 0:
        logger.warning(f"Phát hiện dữ liệu thiếu:\n{missing_counts[missing_counts > 0]}")
        # Phương pháp xử lý mặc định: loại bỏ các dòng thiếu thông tin quan trọng như 'label'
        if 'label' in df.columns:
            df = df.dropna(subset=['label'])
            logger.info("Đã loại bỏ các bản ghi không có nhãn (label).")
    else:
        logger.info("Không phát hiện dữ liệu thiếu.")
    
    return df

def clean_data(df, processed_dir):
    """
    Quy trình làm sạch và chuẩn hóa dữ liệu.
    
    Args:
        df (pd.DataFrame): DataFrame dữ liệu ban đầu.
        processed_dir (str): Thư mục lưu dữ liệu sau khi xử lý.
        
    Returns:
        pd.DataFrame: DataFrame đã được làm sạch.
    """
    logger.info("Bắt đầu quy trình làm sạch dữ liệu...")
    
    df = handle_missing_values(df)
    
    # Chuẩn hóa cột nhãn (label) nếu có
    if 'label' in df.columns:
        # Chuyển đổi nhãn về dạng in thường và xóa khoảng trắng
        df['label'] = df['label'].astype(str).str.strip().str.lower()
        logger.info(f"Các loại nhãn sau khi chuẩn hóa: {df['label'].unique()}")
        
        # Ánh xạ nhãn sang số (ví dụ: benign -> 0, malicious/ryuk -> 1)
        # Tùy thuộc vào yêu cầu dự án, có thể mở rộng cho multi-class
        label_map = {'benign': 0, 'malicious': 1, 'ryuk': 1}
        # Nếu có nhãn không nằm trong map, mặc định gán -1 hoặc cần xử lý riêng
        df['label_encoded'] = df['label'].map(lambda x: label_map.get(x, -1))
        
    # Lưu file đã làm sạch
    ensure_dir(processed_dir)
    output_path = os.path.join(processed_dir, 'cleaned_manifest.csv')
    df.to_csv(output_path, index=False)
    logger.info(f"Đã lưu manifest làm sạch tại: {output_path}")
    
    return df

if __name__ == "__main__":
    # Test chạy trực tiếp module
    try:
        manifest_path = 'data/manifest.csv'
        processed_dir = 'data/processed'
        
        raw_df = load_data(manifest_path)
        cleaned_df = clean_data(raw_df, processed_dir)
        
        print("\n--- Dữ liệu sau khi xử lý ---")
        print(cleaned_df.head())
        
    except Exception as e:
        logger.error(f"Đã xảy ra lỗi trong quá trình thực thi: {e}")
