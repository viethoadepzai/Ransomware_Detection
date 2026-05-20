"""
Research-Grade Feature Matrix Builder (FORENSIC V10)
====================================================

Mục tiêu:
----------
Xây dựng dataset pháp y cấp EDR phục vụ:

1. Stage 1:
   Binary Detection
   SAFE vs ENCRYPTED

2. Stage 2:
   Behavioral Classification
   - Uniform Encryption
   - Partial Encryption
   - Intermittent Encryption
   - Obfuscation
   - Pattern Leakage

Kiến trúc mới:
---------------
Tích hợp:
- Structural Integrity
- Semantic Anomaly
- Entropy Transition
- Flat Entropy Detection
- Evidence Fusion Ready

Roadmap V10:
-------------
[✓] Core Forensic Features
[✓] Structural Damage
[✓] Semantic Anomaly
[✓] Entropy Transition Matrix
[✓] Flat Entropy Detection
[✓] Anti False Positive
[✓] Explainable AI Ready

Author:
--------
Research-grade ransomware forensic pipeline
"""

import os
import random
import traceback
import pandas as pd
import numpy as np

from src.utils import (
    setup_logger,
    load_config,
    ensure_dir
)

from src.crypto_features import (
    extract_all_features,
    extract_block_features,
)

from src.generate_encrypted_data import (
    generate_encrypted_dataset
)

# =========================================================
# LOGGER
# =========================================================

logger = setup_logger(
    'build_dataset_v10',
    'logs/build_dataset.log'
)

# =========================================================
# CONFIG
# =========================================================

BLOCK_SIZE = 2048

MIN_FILE_SIZE_STAGE2 = 4096

MAX_BLOCKS_PER_FILE = 32

RANDOM_SEED = 42

random.seed(RANDOM_SEED)

# =========================================================
# VALIDATION
# =========================================================

REQUIRED_GLOBAL_COLUMNS = [

    # =====================================================
    # IDENTIFICATION
    # =====================================================

    'sample_id',

    'algorithm',

    'file_ext',

    'file_size_bytes',

    # =====================================================
    # RANDOMNESS FEATURES
    # =====================================================

    'entropy',

    'chi_square',

    # =====================================================
    # COMPRESSION / ASCII
    # =====================================================

    'compression_ratio',

    'ascii_ratio',

    'base64_charset_ratio',

    # =====================================================
    # FORMAT FEATURES
    # =====================================================

    'magic_header_score',

    'format_consistency_score',

    'semantic_anomaly_score',

    # =====================================================
    # STRUCTURAL FORENSICS
    # =====================================================

    'structural_damage_score',

    # =====================================================
    # ENTROPY PROFILE
    # =====================================================

    'entropy_std',

    'entropy_mean',

    'entropy_min',

    'entropy_max',

    'entropy_range',

    'high_entropy_ratio',

    'low_entropy_ratio',

    'entropy_spike_count',

    'entropy_periodicity',

    # =====================================================
    # ENTROPY DYNAMICS (SỬA Ở ĐÂY)
    # =====================================================

    'entropy_delta_mean',

    'entropy_delta_std',

    'entropy_shock_score',

    # =====================================================
    # TRANSITION FEATURES (SỬA Ở ĐÂY)
    # =====================================================

    'entropy_transition_count',

    # =====================================================
    # FLATNESS FEATURES
    # =====================================================

    'flat_entropy_score',

    # =====================================================
    # PATTERN FEATURES
    # =====================================================

    'block_repeat_score',

    # =====================================================
    # RANSOMWARE SCORE
    # =====================================================

    'ransomware_score',
]

# =========================================================
# VALIDATE
# =========================================================

def validate_dataframe(df, required_cols, name):

    missing = []

    for col in required_cols:

        if col not in df.columns:

            missing.append(col)

    if missing:

        raise RuntimeError(
            f"{name} missing columns: {missing}"
        )

# =========================================================
# SUMMARY LOGGER
# =========================================================

def log_dataset_summary(df1, df2):

    logger.info("=" * 80)

    logger.info(
        f"Stage1 Shape: {df1.shape}"
    )

    logger.info(
        f"Stage2 Shape: {df2.shape}"
    )

    logger.info("=" * 80)

    logger.info("Stage1 Label Distribution")

    logger.info(
        "\n" +
        str(df1['algorithm'].value_counts())
    )

    logger.info("=" * 80)

    logger.info("Stage2 Label Distribution")

    logger.info(
        "\n" +
        str(df2['algorithm'].value_counts())
    )

    logger.info("=" * 80)

    forensic_cols = [

        'entropy_mean',

        'entropy_range',

        'entropy_std',

        'entropy_transition_count',

        'flat_entropy_score',

        'structural_damage_score',

        'semantic_anomaly_score',

        'format_consistency_score',

        'ransomware_score',
    ]

    logger.info("FORENSIC FEATURE STATISTICS")

    for col in forensic_cols:

        if col in df1.columns:

            logger.info(
                f"{col:<35} "
                f"mean={df1[col].mean():.4f} "
                f"std={df1[col].std():.4f}"
            )

    logger.info("=" * 80)

# =========================================================
# MAIN
# =========================================================

def build_dual_feature_matrices(
    config,
    force_regenerate=False
):

    """
    Build forensic-grade datasets.
    """

    processed_dir = config['data'].get(
        'processed_dir',
        'data/processed'
    )

    ensure_dir(processed_dir)

    stage1_path = os.path.join(
        processed_dir,
        'stage1_global.csv'
    )

    stage2_path = os.path.join(
        processed_dir,
        'stage2_blocks.csv'
    )

    # =====================================================
    # LOAD EXISTING
    # =====================================================

    if (
        os.path.exists(stage1_path)
        and os.path.exists(stage2_path)
        and not force_regenerate
    ):

        logger.info(
            "Loading existing datasets..."
        )

        df1 = pd.read_csv(stage1_path)

        df2 = pd.read_csv(stage2_path)

        validate_dataframe(
            df1,
            REQUIRED_GLOBAL_COLUMNS,
            "Stage1"
        )

        return df1, df2

    # =====================================================
    # START
    # =====================================================

    logger.info("=" * 80)

    logger.info(
        "BUILDING FORENSIC DATASETS V10"
    )

    logger.info("=" * 80)

    # =====================================================
    # GENERATE DATA
    # =====================================================

    metadata = generate_encrypted_dataset(
        config
    )

    if not metadata:

        raise RuntimeError(
            "Dataset generation failed."
        )

    logger.info(
        f"Total samples: {len(metadata)}"
    )

    stage1_rows = []

    stage2_rows = []

    total = len(metadata)

    # =====================================================
    # PROCESS FILES
    # =====================================================

    for idx, meta in enumerate(metadata):

        try:

            if (
                idx == 0
                or (idx + 1) % 100 == 0
            ):

                logger.info(
                    f"Processing {idx+1}/{total} "
                    f"({(idx+1)/total*100:.1f}%)"
                )

            file_path = meta['file_path']

            if not os.path.exists(file_path):

                logger.warning(
                    f"Missing file: {file_path}"
                )

                continue

            # =================================================
            # READ
            # =================================================

            with open(file_path, 'rb') as f:

                data = f.read()

            if not data:

                logger.warning(
                    f"Empty file: {file_path}"
                )

                continue

            # =================================================
            # METADATA
            # =================================================

            sample_id = meta['sample_id']

            algorithm = meta['algorithm']

            file_ext = os.path.splitext(
                file_path
            )[1].lower()

            file_size = len(data)

            # =================================================
            # GLOBAL FEATURES
            # =================================================

            global_features = extract_all_features(
                data
            )

            # =================================================
            # GLOBAL ROW
            # =================================================

            row_g = {

                'sample_id': sample_id,

                'algorithm': algorithm,

                'file_ext': file_ext,

                'file_size_bytes': file_size,
            }

            row_g.update(global_features)

            stage1_rows.append(row_g)

            # =================================================
            # STAGE 2 SKIP
            # =================================================

            if algorithm == 'NoEncryption':
                continue

            if file_size < MIN_FILE_SIZE_STAGE2:
                continue

            # =================================================
            # BLOCK FEATURES
            # =================================================

            block_features = extract_block_features(
                data,
                block_size=BLOCK_SIZE
            )

            if len(block_features) <= 1:
                continue

            # =================================================
            # SKIP HEADER BLOCK
            # =================================================

            block_features = block_features[1:]

            if not block_features:
                continue

            # =================================================
            # RANDOM SAMPLE
            # =================================================

            if len(block_features) > MAX_BLOCKS_PER_FILE:

                block_features = random.sample(
                    block_features,
                    MAX_BLOCKS_PER_FILE
                )

            # =================================================
            # SAVE BLOCK ROWS
            # =================================================

            for block_idx, b_feat in enumerate(block_features):

                row_b = {

                    'sample_id': sample_id,

                    'algorithm': algorithm,

                    'file_ext': file_ext,

                    'block_index': block_idx,

                    'file_size_bytes': file_size,
                }

                row_b.update(b_feat)

                stage2_rows.append(row_b)

        except Exception as e:

            logger.error(
                f"FAILED: {meta}"
            )

            logger.error(str(e))

            logger.error(
                traceback.format_exc()
            )

    # =====================================================
    # DATAFRAMES
    # =====================================================

    logger.info(
        "Creating DataFrames..."
    )

    df1 = pd.DataFrame(stage1_rows)

    df2 = pd.DataFrame(stage2_rows)

    # =====================================================
    # VALIDATION
    # =====================================================

    if len(df1) == 0:

        raise RuntimeError(
            "Stage1 dataset empty."
        )

    if len(df2) == 0:

        raise RuntimeError(
            "Stage2 dataset empty."
        )

    validate_dataframe(
        df1,
        REQUIRED_GLOBAL_COLUMNS,
        "Stage1"
    )

    # =====================================================
    # CLEAN NaN / INF
    # =====================================================

    df1.replace(
        [np.inf, -np.inf],
        0,
        inplace=True
    )

    df1.fillna(
        0,
        inplace=True
    )

    df2.replace(
        [np.inf, -np.inf],
        0,
        inplace=True
    )

    df2.fillna(
        0,
        inplace=True
    )

    # =====================================================
    # SAVE
    # =====================================================

    logger.info(
        "Saving datasets..."
    )

    df1.to_csv(
        stage1_path,
        index=False
    )

    df2.to_csv(
        stage2_path,
        index=False
    )

    # =====================================================
    # SUMMARY
    # =====================================================

    log_dataset_summary(df1, df2)

    logger.info(
        "FORENSIC DATASET BUILD COMPLETED"
    )

    logger.info("=" * 80)

    return df1, df2

# =========================================================
# ENTRYPOINT
# =========================================================

if __name__ == "__main__":

    config = load_config(
        'config/config.yaml'
    )

    df1, df2 = build_dual_feature_matrices(
        config,
        force_regenerate=True
    )

    print("\n" + "=" * 80)

    print("FORENSIC DATASET SUMMARY")

    print("=" * 80)

    print(f"\nStage1 Shape: {df1.shape}")

    print(f"Stage2 Shape: {df2.shape}")

    print("\nStage1 Labels:\n")

    print(
        df1['algorithm'].value_counts()
    )

    print("\nStage2 Labels:\n")

    print(
        df2['algorithm'].value_counts()
    )

    forensic_cols = [

        'entropy_mean',

        'entropy_range',

        'entropy_std',

        'entropy_transition_count',

        'flat_entropy_score',

        'structural_damage_score',

        'semantic_anomaly_score',

        'format_consistency_score',

        'ransomware_score',
    ]

    print("\nFORENSIC FEATURE STATS:\n")

    print(
        df1[forensic_cols]
        .describe()
    )

    print("\nDONE.")