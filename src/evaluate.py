import logging
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, precision_recall_curve, auc
import matplotlib.pyplot as plt
import seaborn as sns
import os

from src.utils import setup_logger, ensure_dir

logger = setup_logger('evaluate', 'logs/evaluate.log')

def evaluate_model(model, X_test, y_test, results_dir='../logs'):
    """
    Đánh giá mô hình bằng các metric phân loại và vẽ Confusion Matrix.
    Đặc biệt quan tâm đến Recall (phát hiện mã độc) và False Positive Rate.
    
    Args:
        model: Đối tượng mô hình (đã huấn luyện).
        X_test (np.ndarray hoặc pd.DataFrame): Dữ liệu đặc trưng tập Test.
        y_test (np.ndarray): Nhãn thực tế.
        results_dir (str): Thư mục lưu biểu đồ kết quả.
    """
    logger.info("Đang tiến hành đánh giá mô hình trên tập Test...")
    
    # Dự đoán
    y_pred = model.predict(X_test)
    
    # Dự đoán xác suất cho ROC-AUC (nếu mô hình hỗ trợ)
    try:
        y_prob = model.predict_proba(X_test)[:, 1]
    except AttributeError:
        logger.warning("Mô hình không hỗ trợ predict_proba. Bỏ qua ROC-AUC.")
        y_prob = None

    # Tính toán các Metrics
    metrics = {
        'Accuracy': accuracy_score(y_test, y_pred),
        'Precision': precision_score(y_test, y_pred, zero_division=0),
        'Recall': recall_score(y_test, y_pred, zero_division=0),
        'F1-Score': f1_score(y_test, y_pred, zero_division=0)
    }
    if y_prob is not None:
        metrics['ROC-AUC'] = roc_auc_score(y_test, y_prob)
        
        # Tính PR-AUC (Precision-Recall AUC) - Chỉ số vàng cho dữ liệu mất cân bằng
        precision_curve, recall_curve, _ = precision_recall_curve(y_test, y_prob)
        metrics['PR-AUC'] = auc(recall_curve, precision_curve)
        
    # In báo cáo
    logger.info("--- BÁO CÁO ĐÁNH GIÁ (EVALUATION REPORT) ---")
    for k, v in metrics.items():
        logger.info(f"{k:<10}: {v:.4f}")
        
    # Tính và vẽ Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    logger.info(f"Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    
    if (tn + fp) > 0:
        fpr = fp / (tn + fp)
        logger.info(f"False Positive Rate (FPR): {fpr:.4f} (Rất quan trọng cần giữ ở mức thấp)")
        
    # Vẽ biểu đồ
    ensure_dir(results_dir)
    cm_path = os.path.join(results_dir, 'confusion_matrix.png')
    plot_confusion_matrix(cm, classes=['Benign', 'Malicious/Ryuk'], save_path=cm_path)
    
    return metrics

def plot_confusion_matrix(cm, classes, save_path):
    """Vẽ và lưu Confusion Matrix."""
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=classes, yticklabels=classes)
    plt.title('Confusion Matrix')
    plt.ylabel('Thực tế (True Label)')
    plt.xlabel('Dự đoán (Predicted Label)')
    plt.tight_layout()
    plt.savefig(save_path)
    plt.close()
    logger.info(f"Đã lưu biểu đồ Confusion Matrix tại: {save_path}")

if __name__ == "__main__":
    logger.info("Mô-đun đánh giá (Evaluate Module).")
    logger.info("Chạy `train.py` để thực thi quy trình huấn luyện và đánh giá.")
