import os
import yaml
import logging

def setup_logger(name, log_file, level=logging.INFO):
    """
    Thiết lập logger chuẩn cho dự án.
    
    Args:
        name (str): Tên module hoặc logger.
        log_file (str): Đường dẫn tới file lưu log.
        level (int): Mức độ log (mặc định: INFO).
        
    Returns:
        logging.Logger: Đối tượng logger.
    """
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Đảm bảo thư mục chứa log tồn tại
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
        
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Tránh duplicate log nếu gọi hàm nhiều lần
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger

def load_config(config_path):
    """
    Tải thông số cấu hình từ file YAML.
    
    Args:
        config_path (str): Đường dẫn file config (.yaml).
        
    Returns:
        dict: Cấu hình dưới dạng dictionary.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Không tìm thấy file cấu hình tại: {config_path}")
        
    with open(config_path, 'r', encoding='utf-8') as f:
        try:
            config = yaml.safe_load(f)
            return config
        except yaml.YAMLError as exc:
            raise RuntimeError(f"Lỗi parse file cấu hình YAML: {exc}")

def ensure_dir(directory):
    """
    Kiểm tra và tạo thư mục nếu chưa tồn tại.
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
        
