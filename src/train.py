import argparse
import logging
import pandas as pd
import numpy as np
import os
import joblib
import json
import random
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import roc_curve, auc
from xgboost import XGBClassifier

from src.utils import setup_logger, load_config, ensure_dir
from src.evaluate import evaluate_model

# ===============================
# SETUP
# ===============================
ensure_dir("logs")
ensure_dir("models")
ensure_dir("data/processed")

logger = setup_logger('train', 'logs/train.log')

def set_seed(seed=42):
    np.random.seed(seed)
    random.seed(seed)

# ===============================
# PREPARE DATA
# ===============================
def prepare_data(config):
    logger.info("Chuẩn bị dữ liệu...")

    processed_dir = config['data'].get('processed_dir', 'data/processed')
    num_samples = config['data'].get('num_samples', 3000)

    # ⚠️ giữ nguyên tên file gốc
    features_path = os.path.join(processed_dir, 'features_matrix.csv')

    need_generate = True

    if os.path.exists(features_path):
        try:
            df = pd.read_csv(features_path)
            if len(df) == num_samples:
                need_generate = False
                logger.info(f"Dataset {num_samples} mẫu đã tồn tại.")
            else:
                logger.warning(f"Dataset hiện tại {len(df)} != {num_samples} → sẽ generate lại")
        except:
            pass

    if need_generate:
        logger.info(f"Đang sinh dataset {num_samples} mẫu...")
        from src.build_dataset import generate_realistic_dataset
        generate_realistic_dataset(num_samples=num_samples, output_path=features_path)

    df = pd.read_csv(features_path)

    if 'label_encoded' not in df.columns:
        raise ValueError("Thiếu label_encoded")

    y = df['label_encoded'].values
    drop_cols = ['label', 'label_encoded', 'sample_id', 'file_name']

    feature_cols = [c for c in df.columns if c not in drop_cols]
    X = df[feature_cols].values

    logger.info(f"Dataset shape: {X.shape}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=config['training'].get('test_size', 0.2),
        random_state=config['training'].get('random_seed', 42),
        stratify=y
    )

    return X_train, X_test, y_train, y_test, feature_cols

# ===============================
# BUILD MODEL
# ===============================
def build_model(config, y_train):
    params = config['model'].get('params', {})
    seed = config['training'].get('random_seed', 42)

    pos = sum(y_train)
    neg = len(y_train) - pos
    scale_pos_weight = neg / pos if pos > 0 else 1

    xgb_params = {
        'use_label_encoder': False,
        'eval_metric': 'logloss',
        'random_state': seed,
        'scale_pos_weight': scale_pos_weight
    }

    xgb_params.update(params)

    return XGBClassifier(**xgb_params)

# ===============================
# TRAIN
# ===============================
def train_model(config):
    logger.info("=== TRAIN START ===")

    set_seed(config['training'].get('random_seed', 42))

    X_train, X_test, y_train, y_test, feature_cols = prepare_data(config)

    base_model = build_model(config, y_train)

    param_dist = {
        'n_estimators': [100, 200],
        'max_depth': [4, 6, 8],
        'learning_rate': [0.01, 0.05, 0.1],
        'subsample': [0.8, 1.0],
        'colsample_bytree': [0.8, 1.0]
    }

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    search = RandomizedSearchCV(
        base_model,
        param_distributions=param_dist,
        n_iter=10,
        scoring='roc_auc',
        cv=cv,
        n_jobs=-1,
        random_state=42
    )

    search.fit(X_train, y_train)

    model = search.best_estimator_

    logger.info(f"Best params: {search.best_params_}")

    # ===============================
    # SAVE MODEL (GIỮ TÊN CŨ)
    # ===============================
    model_path = "models/ryuk_xgboost_model.joblib"
    joblib.dump(model, model_path)

    logger.info(f"Saved model: {model_path}")

    # save features
    with open("models/features_list.json", "w") as f:
        json.dump(feature_cols, f)

    # ===============================
    # EVALUATE
    # ===============================
    evaluate_model(model, X_test, y_test, results_dir='logs')

    # ===============================
    # ROC
    # ===============================
    y_prob = model.predict_proba(X_test)[:,1]
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    roc_auc = auc(fpr, tpr)

    plt.figure()
    plt.plot(fpr, tpr, label=f"AUC={roc_auc:.3f}")
    plt.legend()
    plt.title("ROC Curve")
    plt.savefig("logs/roc_curve.png")
    plt.close()

    # ===============================
    # FEATURE IMPORTANCE
    # ===============================
    try:
        import xgboost as xgb
        plt.figure()
        model.get_booster().feature_names = feature_cols
        xgb.plot_importance(model, max_num_features=10)
        plt.savefig("logs/feature_importance.png")
        plt.close()
    except Exception as e:
        logger.warning(e)

    # ===============================
    # SHAP
    # ===============================
    try:
        import shap
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_test)

        plt.figure()
        shap.summary_plot(shap_values, X_test, feature_names=feature_cols, show=False)
        plt.savefig("logs/shap_summary.png")
        plt.close()
    except Exception as e:
        logger.warning(e)

    logger.info("=== DONE ===")

    return model

# ===============================
# MAIN
# ===============================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=str, default='config/config.yaml')
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        train_model(config)
    except Exception as e:
        logger.error(e)