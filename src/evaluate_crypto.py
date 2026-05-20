"""
Module đánh giá mô hình phân loại thuật toán mã hóa (multi-class).

Bao gồm:
- Confusion matrix heatmap
- Classification report (Precision/Recall/F1 per-class)
- So sánh nhiều mô hình
- So sánh với baseline entropy-only
- Phân tích ECB vs CBC

Tham khảo: Kowalewski & Grześ (2025) - Evaluation metrics
"""
import os
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)
from src.utils import setup_logger, ensure_dir

logger = setup_logger('evaluate_crypto', 'logs/evaluate_crypto.log')

# Sử dụng font hỗ trợ Unicode
plt.rcParams['font.family'] = 'DejaVu Sans'


def evaluate_multiclass_model(model, X_test, y_test, label_names, results_dir='logs'):
    """
    Đánh giá toàn diện mô hình phân loại đa lớp.
    
    Args:
        model: Mô hình đã huấn luyện
        X_test: Dữ liệu test
        y_test: Nhãn thực tế (encoded)
        label_names: List tên nhãn (["AES_CBC", "AES_ECB", ...])
        results_dir: Thư mục lưu kết quả
    
    Returns:
        dict: Tất cả metrics
    """
    ensure_dir(results_dir)
    
    logger.info("=" * 60)
    logger.info("ĐÁNH GIÁ MÔ HÌNH PHÂN LOẠI THUẬT TOÁN MÃ HÓA")
    logger.info("=" * 60)
    
    y_pred = model.predict(X_test)
    
    # 1. Overall Metrics
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision_macro': precision_score(y_test, y_pred, average='macro', zero_division=0),
        'recall_macro': recall_score(y_test, y_pred, average='macro', zero_division=0),
        'f1_macro': f1_score(y_test, y_pred, average='macro', zero_division=0),
        'precision_weighted': precision_score(y_test, y_pred, average='weighted', zero_division=0),
        'recall_weighted': recall_score(y_test, y_pred, average='weighted', zero_division=0),
        'f1_weighted': f1_score(y_test, y_pred, average='weighted', zero_division=0),
    }
    
    logger.info(f"\n--- OVERALL METRICS ---")
    logger.info(f"  Accuracy:           {metrics['accuracy']:.4f}")
    logger.info(f"  Precision (macro):  {metrics['precision_macro']:.4f}")
    logger.info(f"  Recall (macro):     {metrics['recall_macro']:.4f}")
    logger.info(f"  F1-Score (macro):   {metrics['f1_macro']:.4f}")
    logger.info(f"  F1-Score (weighted):{metrics['f1_weighted']:.4f}")
    
    # 2. Per-class Report
    report = classification_report(y_test, y_pred, target_names=label_names, zero_division=0)
    logger.info(f"\n--- CLASSIFICATION REPORT ---\n{report}")
    
    # Lưu report vào file
    report_path = os.path.join(results_dir, 'classification_report.txt')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=== CLASSIFICATION REPORT ===\n\n")
        f.write(f"Accuracy: {metrics['accuracy']:.4f}\n")
        f.write(f"F1-Score (macro): {metrics['f1_macro']:.4f}\n")
        f.write(f"F1-Score (weighted): {metrics['f1_weighted']:.4f}\n\n")
        f.write(report)
    
    # 3. Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    plot_confusion_matrix(cm, label_names, 
                         os.path.join(results_dir, 'confusion_matrix_crypto.png'))
    
    # 4. Per-class F1 bar chart
    plot_per_class_f1(y_test, y_pred, label_names,
                      os.path.join(results_dir, 'f1_per_class.png'))
    
    metrics['confusion_matrix'] = cm
    metrics['classification_report'] = report
    
    return metrics


def plot_confusion_matrix(cm, class_names, save_path):
    """Vẽ confusion matrix heatmap cho multi-class."""
    fig, ax = plt.subplots(figsize=(12, 10))
    
    # Chuẩn hóa theo hàng (tỷ lệ phần trăm)
    cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    cm_normalized = np.nan_to_num(cm_normalized)
    
    # Vẽ heatmap với giá trị gốc + phần trăm
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=class_names, yticklabels=class_names,
                ax=ax, linewidths=0.5, linecolor='gray')
    
    ax.set_title('Confusion Matrix - Encryption Algorithm Classification',
                fontsize=14, fontweight='bold', pad=20)
    ax.set_ylabel('True Algorithm', fontsize=12)
    ax.set_xlabel('Predicted Algorithm', fontsize=12)
    
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    logger.info(f"Confusion matrix saved: {save_path}")


def plot_per_class_f1(y_test, y_pred, class_names, save_path):
    """Vẽ biểu đồ F1-score cho từng thuật toán."""
    f1_scores = f1_score(y_test, y_pred, average=None, zero_division=0)
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    colors = plt.cm.Set3(np.linspace(0, 1, len(class_names)))
    bars = ax.bar(range(len(class_names)), f1_scores, color=colors, 
                  edgecolor='gray', linewidth=0.5)
    
    ax.set_xticks(range(len(class_names)))
    ax.set_xticklabels(class_names, rotation=45, ha='right', fontsize=10)
    ax.set_ylabel('F1-Score', fontsize=12)
    ax.set_title('F1-Score per Encryption Algorithm', fontsize=14, fontweight='bold')
    ax.set_ylim(0, 1.05)
    
    # Thêm giá trị lên đầu mỗi bar
    for bar, score in zip(bars, f1_scores):
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.01,
               f'{score:.3f}', ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    ax.axhline(y=np.mean(f1_scores), color='red', linestyle='--', alpha=0.7,
              label=f'Average F1: {np.mean(f1_scores):.3f}')
    ax.legend(fontsize=10)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    logger.info(f"F1 per-class chart saved: {save_path}")


def compare_models(results_dict, save_path='logs/model_comparison.png'):
    """
    So sánh nhiều mô hình trên cùng một biểu đồ.
    
    Args:
        results_dict: {model_name: metrics_dict}
        save_path: Đường dẫn lưu biểu đồ
    """
    ensure_dir(os.path.dirname(save_path))
    
    model_names = list(results_dict.keys())
    metric_keys = ['accuracy', 'f1_macro', 'precision_macro', 'recall_macro']
    metric_labels = ['Accuracy', 'F1 (Macro)', 'Precision (Macro)', 'Recall (Macro)']
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    x = np.arange(len(model_names))
    width = 0.2
    
    colors = ['#3498db', '#e74c3c', '#2ecc71', '#f39c12']
    
    for i, (key, label) in enumerate(zip(metric_keys, metric_labels)):
        values = [results_dict[m].get(key, 0) for m in model_names]
        bars = ax.bar(x + i * width, values, width, label=label, color=colors[i], alpha=0.85)
        
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.005,
                   f'{val:.3f}', ha='center', va='bottom', fontsize=8)
    
    ax.set_xticks(x + width * 1.5)
    ax.set_xticklabels(model_names, fontsize=11)
    ax.set_ylabel('Score', fontsize=12)
    ax.set_title('Model Comparison - Encryption Algorithm Classification',
                fontsize=14, fontweight='bold')
    ax.set_ylim(0, 1.15)
    ax.legend(loc='upper right', fontsize=10)
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(save_path, dpi=150, bbox_inches='tight')
    plt.close()
    
    logger.info(f"Model comparison chart saved: {save_path}")
    
    # In bảng so sánh
    logger.info("\n=== MODEL COMPARISON TABLE ===")
    header = f"{'Model':<20}" + "".join(f"{l:<18}" for l in metric_labels)
    logger.info(header)
    logger.info("-" * len(header))
    for name in model_names:
        row = f"{name:<20}"
        for key in metric_keys:
            row += f"{results_dict[name].get(key, 0):<18.4f}"
        logger.info(row)


def evaluate_baseline_entropy(X_test, y_test, label_names, entropy_col_idx=0,
                               entropy_threshold=7.0):
    """
    Baseline: Phát hiện mã hóa chỉ dựa vào entropy (giống Autopsy).
    
    Phương pháp: Nếu entropy > threshold → "encrypted" (chung), ngược lại → "NoEncryption"
    Không phân biệt được giữa các thuật toán → accuracy thấp.
    
    Args:
        X_test: Feature matrix
        y_test: True labels
        label_names: List tên nhãn
        entropy_col_idx: Index cột entropy trong X_test
        entropy_threshold: Ngưỡng entropy
    
    Returns:
        dict: Metrics của baseline
    """
    logger.info(f"\n=== BASELINE: Entropy-only (threshold={entropy_threshold}) ===")
    
    # Tìm index của NoEncryption
    no_enc_idx = label_names.index("NoEncryption") if "NoEncryption" in label_names else -1
    
    # Baseline prediction: encrypted (bất kỳ lớp nào != NoEncryption) vs NoEncryption
    entropy_values = X_test[:, entropy_col_idx]
    
    # Binary prediction: encrypted (1) vs not encrypted (0)
    baseline_pred_binary = (entropy_values > entropy_threshold).astype(int)
    true_binary = (y_test != no_enc_idx).astype(int)
    
    binary_acc = accuracy_score(true_binary, baseline_pred_binary)
    binary_f1 = f1_score(true_binary, baseline_pred_binary, zero_division=0)
    
    logger.info(f"  Binary Detection (encrypted vs not):")
    logger.info(f"    Accuracy:  {binary_acc:.4f}")
    logger.info(f"    F1-Score:  {binary_f1:.4f}")
    
    # Baseline KHÔNG THỂ phân loại thuật toán cụ thể
    # Gán tất cả encrypted → class phổ biến nhất (AES_ECB)
    most_common_enc = 0  # dummy
    baseline_pred_multi = np.where(
        entropy_values > entropy_threshold, most_common_enc, no_enc_idx
    )
    
    multi_acc = accuracy_score(y_test, baseline_pred_multi)
    
    logger.info(f"  Multi-class (cannot distinguish algorithms):")
    logger.info(f"    Accuracy:  {multi_acc:.4f}")
    logger.info(f"    (Baseline chỉ phát hiện 'có mã hóa' hay không, không phân loại thuật toán)")
    
    return {
        'binary_accuracy': binary_acc,
        'binary_f1': binary_f1,
        'multiclass_accuracy': multi_acc,
        'method': f'Entropy threshold > {entropy_threshold}',
    }


def analyze_ecb_vs_cbc(y_test, y_pred, label_names, results_dir='logs'):
    """
    Phân tích hiệu quả phát hiện ECB vs CBC.
    Dự kiến: ECB dễ phát hiện hơn CBC (do ECB deterministic).
    """
    logger.info("\n=== PHÂN TÍCH ECB vs CBC ===")
    
    ecb_classes = [i for i, name in enumerate(label_names) if 'ECB' in name]
    cbc_classes = [i for i, name in enumerate(label_names) if 'CBC' in name]
    
    if ecb_classes:
        ecb_mask = np.isin(y_test, ecb_classes)
        if ecb_mask.sum() > 0:
            ecb_acc = accuracy_score(y_test[ecb_mask], y_pred[ecb_mask])
            ecb_f1 = f1_score(y_test[ecb_mask], y_pred[ecb_mask], average='macro', zero_division=0)
            logger.info(f"  ECB modes: Accuracy={ecb_acc:.4f}, F1={ecb_f1:.4f} (N={ecb_mask.sum()})")
    
    if cbc_classes:
        cbc_mask = np.isin(y_test, cbc_classes)
        if cbc_mask.sum() > 0:
            cbc_acc = accuracy_score(y_test[cbc_mask], y_pred[cbc_mask])
            cbc_f1 = f1_score(y_test[cbc_mask], y_pred[cbc_mask], average='macro', zero_division=0)
            logger.info(f"  CBC modes: Accuracy={cbc_acc:.4f}, F1={cbc_f1:.4f} (N={cbc_mask.sum()})")
    
    if ecb_classes and cbc_classes:
        logger.info("  → ECB thường dễ phân loại hơn CBC vì ECB không có IV ngẫu nhiên")
        logger.info("  → CBC với IV khác nhau tạo output ngẫu nhiên hơn, khó phân biệt")


if __name__ == "__main__":
    logger.info("Module evaluate_crypto sẵn sàng.")
    logger.info("Chạy 'python -m src.train_crypto' để huấn luyện và đánh giá.")
