# train_crypto.py

"""
Research-Grade Forensic Crypto Training Pipeline (FINAL V10)
============================================================

Stage 1:
---------
Global Forensic Risk Detector

Detect:
    - Safe Files
    - Compressed Files
    - Encrypted Files
    - Ransomware Artifacts
    - Base64 Obfuscation
    - Structural Damage

Stage 2:
---------
Behavioral Encryption Pattern Analyzer

Detect:
    - Uniform Encryption
    - Intermittent Encryption
    - Partial Encryption
    - Pattern Leakage
    - ECB Leakage
    - Header Corruption
    - Semantic Inconsistency

V10 Improvements:
-----------------
1. Evidence-Fusion feature learning
2. Structural forensic awareness
3. Semantic anomaly learning
4. Entropy transition dynamics
5. Flat entropy behavior
6. Compression-safe learning
7. Group-aware anti-leak split
8. ROC threshold optimization
9. Calibration learning
10. Research-grade metrics
11. Feature importance export
12. Enterprise forensic architecture
"""

import os
import json
import random
import joblib
import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import GroupShuffleSplit

from sklearn.ensemble import RandomForestClassifier

from sklearn.preprocessing import LabelEncoder

from sklearn.calibration import (
    CalibratedClassifierCV,
    calibration_curve
)

from sklearn.metrics import (

    accuracy_score,

    f1_score,

    classification_report,

    confusion_matrix,

    roc_auc_score,

    roc_curve,

    matthews_corrcoef,

    balanced_accuracy_score,

    RocCurveDisplay,
)

from src.utils import (
    setup_logger,
    ensure_dir,
    load_config
)

from src.build_crypto_dataset import (
    build_dual_feature_matrices
)

# =========================================================
# REPRODUCIBILITY
# =========================================================

SEED = 42

random.seed(SEED)

np.random.seed(SEED)

# =========================================================
# LOGGER
# =========================================================

logger = setup_logger(
    "train_crypto",
    "logs/train_crypto.log"
)

# =========================================================
# FEATURE SETS
# =========================================================

STAGE1_FEATURES = [

    # =====================================================
    # CORE ENTROPY
    # =====================================================

    'entropy',

    # =====================================================
    # STATISTICS
    # =====================================================

    'mean',

    'std_dev',

    'variance',

    'skewness',

    'kurtosis',

    'median',

    # =====================================================
    # RANDOMNESS
    # =====================================================

    'chi_square',

    # =====================================================
    # COMPRESSION / ASCII
    # =====================================================

    'compression_ratio',

    'ascii_ratio',

    'base64_charset_ratio',

    # =====================================================
    # STRUCTURAL FORENSICS
    # =====================================================

    'magic_header_score',

    'structural_damage_score',

    'format_consistency_score',

    'semantic_anomaly_score',

    # =====================================================
    # ECB / PATTERN
    # =====================================================

    'block_repeat_score',

    # =====================================================
    # WINDOW ENTROPY
    # =====================================================

    'entropy_std',

    'entropy_shock_score',

    # =====================================================
    # ADVANCED ENTROPY PROFILE
    # =====================================================

    'entropy_mean',

    'entropy_min',

    'entropy_max',

    'entropy_range',

    'high_entropy_ratio',

    'low_entropy_ratio',

    'entropy_spike_count',

    'entropy_periodicity',

    # =====================================================
    # ENTROPY TRANSITIONS
    # =====================================================

    'entropy_transition_count',

    # =====================================================
    # FLATNESS
    # =====================================================

    'flat_entropy_score',

    # =====================================================
    # BEHAVIORAL RISK
    # =====================================================

    'ransomware_score',

    # =====================================================
    # CONTEXT
    # =====================================================

    'file_size',
]

# =========================================================

STAGE2_FEATURES = [

    # =====================================================
    # CORE ENTROPY
    # =====================================================

    'entropy',

    # =====================================================
    # STATISTICS
    # =====================================================

    'std_dev',

    'skewness',

    'kurtosis',

    # =====================================================
    # RANDOMNESS
    # =====================================================

    'chi_square',

    # =====================================================
    # COMPRESSION / ASCII
    # =====================================================

    'compression_ratio',

    'ascii_ratio',

    'base64_charset_ratio',

    # =====================================================
    # STRUCTURAL FORENSICS
    # =====================================================

    'structural_damage_score',

    'format_consistency_score',

    'semantic_anomaly_score',

    # =====================================================
    # ECB LEAKAGE
    # =====================================================

    'block_repeat_score',

    # =====================================================
    # ENTROPY DYNAMICS
    # =====================================================

    'entropy_std',

    'entropy_delta_mean',    

    'entropy_delta_std',

    'entropy_shock_score',

    # =====================================================
    # ENTROPY PROFILE
    # =====================================================

    'entropy_mean',

    'entropy_min',

    'entropy_max',

    'entropy_range',

    'high_entropy_ratio',

    'low_entropy_ratio',

    'entropy_spike_count',

    'entropy_periodicity',

    # =====================================================
    # ENTROPY TRANSITIONS
    # =====================================================

    'entropy_transition_count',

    # =====================================================
    # FLATNESS
    # =====================================================

    'flat_entropy_score',

    # =====================================================
    # AGGREGATED RISK
    # =====================================================

    'ransomware_score',
]

# =========================================================
# BASELINE
# =========================================================

def entropy_baseline(
    entropy,
    threshold=7.2
):

    return int(entropy >= threshold)

# =========================================================
# THRESHOLD OPTIMIZATION
# =========================================================

def find_optimal_threshold(
    y_true,
    y_prob
):

    fpr, tpr, thresholds = roc_curve(
        y_true,
        y_prob
    )

    j_scores = tpr - fpr

    best_idx = np.argmax(j_scores)

    return {

        "threshold": float(
            thresholds[best_idx]
        ),

        "tpr": float(
            tpr[best_idx]
        ),

        "fpr": float(
            fpr[best_idx]
        ),

        "j_score": float(
            j_scores[best_idx]
        )
    }

# =========================================================
# SECURITY METRICS
# =========================================================

def compute_security_metrics(
    y_true,
    y_pred
):

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred
    ).ravel()

    fpr = fp / (fp + tn + 1e-9)

    fnr = fn / (fn + tp + 1e-9)

    tpr = tp / (tp + fn + 1e-9)

    return {

        "TPR": float(tpr),

        "FPR": float(fpr),

        "FNR": float(fnr),
    }

# =========================================================
# VISUALIZATION
# =========================================================

def plot_confusion_matrix(
    y_true,
    y_pred,
    labels,
    title,
    out_dir
):

    cm = confusion_matrix(
        y_true,
        y_pred
    )

    plt.figure(figsize=(10, 8))

    sns.heatmap(
        cm,
        annot=True,
        fmt='d',
        cmap='Blues',
        xticklabels=labels,
        yticklabels=labels
    )

    plt.title(title)

    plt.ylabel('Actual')

    plt.xlabel('Predicted')

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            out_dir,
            f"cm_{title.lower().replace(' ', '_')}.png"
        )
    )

    plt.close()

# =========================================================

def plot_feature_importance(
    model,
    features,
    title,
    out_dir
):

    importances = model.feature_importances_

    indices = np.argsort(importances)[::-1]

    df = pd.DataFrame({

        "feature": features,

        "importance": importances
    })

    df = df.sort_values(
        by='importance',
        ascending=False
    )

    df.to_csv(

        os.path.join(
            out_dir,
            f"fi_{title.lower().replace(' ', '_')}.csv"
        ),

        index=False
    )

    plt.figure(figsize=(16, 8))

    plt.title(title)

    plt.bar(
        range(len(features)),
        importances[indices]
    )

    plt.xticks(
        range(len(features)),
        [features[i] for i in indices],
        rotation=75,
        ha='right'
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            out_dir,
            f"fi_{title.lower().replace(' ', '_')}.png"
        )
    )

    plt.close()

# =========================================================

def plot_roc_curve(
    y_true,
    y_prob,
    title,
    out_dir
):

    auc = roc_auc_score(
        y_true,
        y_prob
    )

    display = RocCurveDisplay.from_predictions(
        y_true,
        y_prob
    )

    display.ax_.set_title(
        f"ROC Curve ({auc:.4f})"
    )

    plt.plot(
        [0, 1],
        [0, 1],
        linestyle='--'
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            out_dir,
            f"roc_{title.lower().replace(' ', '_')}.png"
        )
    )

    plt.close()

# =========================================================

def plot_calibration_curve(
    y_true,
    y_prob,
    out_dir
):

    prob_true, prob_pred = calibration_curve(
        y_true,
        y_prob,
        n_bins=10
    )

    plt.figure(figsize=(6, 6))

    plt.plot(
        prob_pred,
        prob_true,
        marker='o'
    )

    plt.plot(
        [0, 1],
        [0, 1],
        linestyle='--'
    )

    plt.xlabel(
        'Predicted Probability'
    )

    plt.ylabel(
        'True Probability'
    )

    plt.title(
        'Calibration Curve'
    )

    plt.tight_layout()

    plt.savefig(
        os.path.join(
            out_dir,
            'calibration_curve.png'
        )
    )

    plt.close()

# =========================================================
# STAGE 1
# =========================================================

def train_stage1(df1):

    logger.info("=" * 80)

    logger.info(
        "STAGE 1 - FORENSIC RISK DETECTOR"
    )

    logger.info("=" * 80)

    y = (
        df1['algorithm'] != 'NoEncryption'
    ).astype(int).values

    X = df1[
        STAGE1_FEATURES
    ].values

    groups = df1[
        'sample_id'
    ].values

    # =====================================================
    # GROUP SPLIT
    # =====================================================

    gss = GroupShuffleSplit(

        n_splits=1,

        test_size=0.2,

        random_state=SEED
    )

    train_idx, test_idx = next(
        gss.split(X, y, groups)
    )

    X_train, y_train = (
        X[train_idx],
        y[train_idx]
    )

    X_test, y_test = (
        X[test_idx],
        y[test_idx]
    )

    logger.info(
        f"Train samples: {len(X_train)}"
    )

    logger.info(
        f"Test samples : {len(X_test)}"
    )

    # =====================================================
    # MODEL
    # =====================================================

    rf = RandomForestClassifier(

        n_estimators=600,

        max_depth=16,

        min_samples_leaf=2,

        class_weight='balanced',

        random_state=SEED,

        n_jobs=-1
    )

    rf.fit(
        X_train,
        y_train
    )

    # =====================================================
    # FEATURE IMPORTANCE
    # =====================================================

    plot_feature_importance(

        rf,

        STAGE1_FEATURES,

        'Stage1',

        'logs/artifacts'
    )

    # =====================================================
    # CALIBRATION
    # =====================================================

    calibrated_model = CalibratedClassifierCV(

        estimator=rf,

        method='sigmoid',

        cv=5
    )

    calibrated_model.fit(
        X_train,
        y_train
    )

    # =====================================================
    # PREDICT
    # =====================================================

    y_prob = calibrated_model.predict_proba(
        X_test
    )[:, 1]

    optimal = find_optimal_threshold(
        y_test,
        y_prob
    )

    threshold = optimal['threshold']

    y_pred = (
        y_prob >= threshold
    ).astype(int)

    # =====================================================
    # METRICS
    # =====================================================

    acc = accuracy_score(
        y_test,
        y_pred
    )

    f1 = f1_score(
        y_test,
        y_pred
    )

    auc = roc_auc_score(
        y_test,
        y_prob
    )

    bal_acc = balanced_accuracy_score(
        y_test,
        y_pred
    )

    mcc = matthews_corrcoef(
        y_test,
        y_pred
    )

    sec = compute_security_metrics(
        y_test,
        y_pred
    )

    logger.info(f"Accuracy          : {acc:.4f}")
    logger.info(f"F1 Score          : {f1:.4f}")
    logger.info(f"ROC-AUC           : {auc:.4f}")
    logger.info(f"Balanced Accuracy : {bal_acc:.4f}")
    logger.info(f"MCC               : {mcc:.4f}")
    logger.info(f"TPR               : {sec['TPR']:.4f}")
    logger.info(f"FPR               : {sec['FPR']:.4f}")
    logger.info(f"FNR               : {sec['FNR']:.4f}")

    logger.info(

        "\n" +

        classification_report(

            y_test,

            y_pred,

            target_names=[
                'Safe',
                'Encrypted'
            ]
        )
    )

    # =====================================================
    # BASELINE
    # =====================================================

    entropy_values = df1.iloc[
        test_idx
    ]['entropy'].values

    baseline_preds = np.array([

        entropy_baseline(v)

        for v in entropy_values
    ])

    baseline_acc = accuracy_score(

        y_test,

        baseline_preds
    )

    logger.info(
        f"Entropy Baseline Accuracy: {baseline_acc:.4f}"
    )

    # =====================================================
    # VISUALIZATION
    # =====================================================

    plot_confusion_matrix(

        y_test,

        y_pred,

        ['Safe', 'Encrypted'],

        'Stage1',

        'logs/artifacts'
    )

    plot_roc_curve(

        y_test,

        y_prob,

        'Stage1',

        'logs/artifacts'
    )

    plot_calibration_curve(

        y_test,

        y_prob,

        'logs/artifacts'
    )

    # =====================================================
    # SAVE
    # =====================================================

    joblib.dump(

        calibrated_model,

        'models/stage1_binary.joblib'
    )

    logger.info(
        "Stage1 model saved."
    )

    return threshold

# =========================================================
# STAGE 2
# =========================================================

def train_stage2(df2):

    logger.info("=" * 80)

    logger.info(
        "STAGE 2 - FORENSIC BEHAVIOR ANALYZER"
    )

    logger.info("=" * 80)

    df2 = df2[
        df2['algorithm'] != 'NoEncryption'
    ].copy()

    le = LabelEncoder()

    y = le.fit_transform(
        df2['algorithm']
    )

    X = df2[
        STAGE2_FEATURES
    ].values

    groups = df2[
        'sample_id'
    ].values

    label_names = list(
        le.classes_
    )

    joblib.dump(
        le,
        'models/stage2_label_encoder.joblib'
    )

    # =====================================================
    # GROUP SPLIT
    # =====================================================

    gss = GroupShuffleSplit(

        n_splits=1,

        test_size=0.2,

        random_state=SEED
    )

    train_idx, test_idx = next(
        gss.split(X, y, groups)
    )

    X_train, y_train = (
        X[train_idx],
        y[train_idx]
    )

    X_test, y_test = (
        X[test_idx],
        y[test_idx]
    )

    logger.info(
        f"Train samples: {len(X_train)}"
    )

    logger.info(
        f"Test samples : {len(X_test)}"
    )

    # =====================================================
    # MODEL
    # =====================================================

    model = RandomForestClassifier(

        n_estimators=700,

        max_depth=None,

        min_samples_leaf=2,

        class_weight='balanced',

        random_state=SEED,

        n_jobs=-1
    )

    model.fit(
        X_train,
        y_train
    )

    # =====================================================
    # PREDICT
    # =====================================================

    y_pred = model.predict(X_test)

    # =====================================================
    # METRICS
    # =====================================================

    acc = accuracy_score(
        y_test,
        y_pred
    )

    f1 = f1_score(
        y_test,
        y_pred,
        average='macro'
    )

    bal_acc = balanced_accuracy_score(
        y_test,
        y_pred
    )

    mcc = matthews_corrcoef(
        y_test,
        y_pred
    )

    logger.info(f"Accuracy          : {acc:.4f}")
    logger.info(f"F1 Macro          : {f1:.4f}")
    logger.info(f"Balanced Accuracy : {bal_acc:.4f}")
    logger.info(f"MCC               : {mcc:.4f}")

    logger.info(

        "\n" +

        classification_report(

            y_test,

            y_pred,

            target_names=label_names
        )
    )

    # =====================================================
    # VISUALIZATION
    # =====================================================

    plot_confusion_matrix(

        y_test,

        y_pred,

        label_names,

        'Stage2',

        'logs/artifacts'
    )

    plot_feature_importance(

        model,

        STAGE2_FEATURES,

        'Stage2',

        'logs/artifacts'
    )

    # =====================================================
    # SAVE
    # =====================================================

    joblib.dump(
        model,
        'models/stage2_multiclass.joblib'
    )

    logger.info(
        "Stage2 model saved."
    )

# =========================================================
# SAVE METADATA
# =========================================================

def save_metadata(threshold):

    metadata = {

        "version": "V10_FORENSIC_EDR",

        "seed": SEED,

        "stage1_threshold": threshold,

        "stage1_features": STAGE1_FEATURES,

        "stage2_features": STAGE2_FEATURES,
    }

    with open(

        'models/model_metadata.json',

        'w',

        encoding='utf-8'
    ) as f:

        json.dump(
            metadata,
            f,
            indent=2
        )

# =========================================================
# MAIN
# =========================================================

def main():

    ensure_dir('models')

    ensure_dir('logs')

    ensure_dir('logs/artifacts')

    config = load_config(
        'config/config.yaml'
    )

    logger.info(
        "Loading datasets..."
    )

    # =====================================================
    # LOAD DATASETS
    # =====================================================

    df_stage1, df_stage2 = (

        build_dual_feature_matrices(

            config,

            force_regenerate=False
        )
    )

    logger.info(
        f"Stage1 dataset size: {len(df_stage1)}"
    )

    logger.info(
        f"Stage2 dataset size: {len(df_stage2)}"
    )

    # =====================================================
    # TRAIN
    # =====================================================

    threshold = train_stage1(
        df_stage1
    )

    train_stage2(
        df_stage2
    )

    # =====================================================
    # SAVE METADATA
    # =====================================================

    save_metadata(
        threshold
    )

    logger.info("=" * 80)

    logger.info(
        "TRAINING COMPLETED SUCCESSFULLY"
    )

    logger.info("=" * 80)

# =========================================================
# ENTRY
# =========================================================

if __name__ == '__main__':
    main()