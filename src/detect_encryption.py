# detect_encryption.py

"""
AI Encryption Detection System (FINAL V11 - Fusion EDR Engine)
==============================================================

Enterprise Research Architecture
--------------------------------
Stage 1:
    Whole-file AI behavioral detector

Stage 2:
    Sliding-window crypto behavior analysis

Stage 3:
    Evidence Fusion Engine

Stage 4:
    Explainable EDR Decision Layer

Behavior Classes
----------------
- Uniform Encryption
- Intermittent Encryption
- Partial Encryption
- Obfuscation
- Compressed / Random

Major Improvements V11
----------------------
✓ Fusion Risk Formula
✓ Explainable AI Evidence
✓ Structural Damage Analysis
✓ Semantic Anomaly Analysis
✓ Entropy Transition Detection
✓ Flat Entropy Detection
✓ Smart Override Engine
✓ Anti-stage1-bypass
✓ mmap-safe scanning
✓ Large file support
✓ Enterprise-style JSON output
✓ Risk-level normalization
✓ GUI-compatible output
"""

import os
import json
import mmap
import argparse
import joblib
import numpy as np
import zipfile
from PIL import Image
import PyPDF2

from collections import Counter

from src.crypto_features import (
    extract_all_features
)

from src.utils import (
    setup_logger
)

# =========================================================
# LOGGER
# =========================================================

logger = setup_logger(
    'detect_encryption',
    'logs/detect_encryption.log'
)

# =========================================================
# MODEL PATHS
# =========================================================

MODEL_STAGE1 = 'models/stage1_binary.joblib'

MODEL_STAGE2 = 'models/stage2_multiclass.joblib'

LABEL_ENCODER = 'models/stage2_label_encoder.joblib'

METADATA_PATH = 'models/model_metadata.json'

# =========================================================
# CONFIG
# =========================================================

MIN_FILE_SIZE = 256

MAX_FILE_SIZE = (
    20 * 1024 * 1024 * 1024
)

GLOBAL_SCAN_LIMIT = (
    4 * 1024 * 1024
)

WINDOW_STEP_RATIO = 0.5

SMALL_FILE = 32 * 1024

MEDIUM_FILE = 1024 * 1024

BLOCK_SMALL = 512

BLOCK_MEDIUM = 2048

BLOCK_LARGE = 4096

# =========================================================
# FUSION WEIGHTS
# =========================================================

W_AI = 0.35

W_BEHAVIOR = 0.30

W_STRUCTURAL = 0.20

W_ANOMALY = 0.05

W_SURVIVABILITY = 0.40

# =========================================================
# THRESHOLDS
# =========================================================

ENCRYPTION_THRESHOLD = 0.55

OVERRIDE_THRESHOLD = 0.70

# =========================================================
# LOAD MODELS
# =========================================================

def load_models():

    required = [

        MODEL_STAGE1,

        MODEL_STAGE2,

        LABEL_ENCODER,

        METADATA_PATH
    ]

    for path in required:

        if not os.path.exists(path):

            raise FileNotFoundError(
                f"Missing model file: {path}"
            )

    model1 = joblib.load(
        MODEL_STAGE1
    )

    model2 = joblib.load(
        MODEL_STAGE2
    )

    le2 = joblib.load(
        LABEL_ENCODER
    )

    with open(
        METADATA_PATH,
        'r',
        encoding='utf-8'
    ) as f:

        metadata = json.load(f)

    cols_s1 = metadata[
        'stage1_features'
    ]

    cols_s2 = metadata[
        'stage2_features'
    ]

    logger.info(
        "Models loaded successfully"
    )

    return (

        model1,

        model2,

        le2,

        cols_s1,

        cols_s2
    )

# =========================================================
# FEATURE VECTOR
# =========================================================

def extract_vector(
    features_dict,
    columns
):

    vec = []

    missing = []

    for c in columns:

        if c not in features_dict:

            missing.append(c)

        vec.append(
            features_dict.get(c, 0.0)
        )

    if missing:

        logger.warning(
            f"Missing features: {missing}"
        )

    return np.array(vec).reshape(1, -1)

# =========================================================
# BLOCK SIZE
# =========================================================

def get_block_size(file_size):

    if file_size < SMALL_FILE:

        return BLOCK_SMALL

    elif file_size < MEDIUM_FILE:

        return BLOCK_MEDIUM

    return BLOCK_LARGE

# =========================================================
# KNOWN RANSOMWARE EXTENSIONS
# =========================================================

RANSOMWARE_EXTENSIONS = {
    '.lockbit', '.locked', '.enc', '.encrypted',
    '.ryk', '.ryuk', '.ransom', '.crypt',
    '.wcry', '.wncry', '.locky', '.cerber',
    '.zepto', '.thor', '.aesir', '.osiris',
    '.dharma', '.phobos', '.rapid', '.gandcrab',
    '.sodinokibi', '.revil', '.conti', '.hive',
    '.blackcat', '.alphv', '.play', '.royal',
    '.akira', '.medusa', '.rhysida',
    '.crypted', '.encrypt', '.pays', '.pays2',
}

def get_real_extension(file_path):

    name = os.path.basename(file_path).lower()

    # Check if the LAST extension is a ransomware indicator
    last_ext = os.path.splitext(name)[1]

    if last_ext in RANSOMWARE_EXTENSIONS:
        return last_ext

    parts = name.split('.')

    if len(parts) >= 3:

        return '.' + parts[-2]

    return last_ext

# =========================================================
# MEMORY SAFE READER
# =========================================================

def read_sample_bytes(
    file_path,
    max_bytes=GLOBAL_SCAN_LIMIT
):

    file_size = os.path.getsize(
        file_path
    )

    sample_size = min(
        file_size,
        max_bytes
    )

    with open(file_path, 'rb') as f:

        with mmap.mmap(
            f.fileno(),
            length=0,
            access=mmap.ACCESS_READ
        ) as mm:

            return mm[:sample_size]
# =========================================================
# SEMANTIC INTEGRITY ENGINE (STAGE 3)
# =========================================================

def semantic_pdf_integrity(file_path):
    try:
        with open(file_path, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            num_pages = len(reader.pages)
            if num_pages == 0: return 0.2

            # Phân tích ngữ nghĩa: Trích xuất text thử để check Stream Decode
            success_pages = 0
            check_pages = min(3, num_pages) # Check tối đa 3 trang để tối ưu tốc độ
            for i in range(check_pages):
                try:
                    text = reader.pages[i].extract_text()
                    if text is not None and len(text.strip()) >= 0:
                        success_pages += 1
                except Exception:
                    pass
            
            # Base 0.4 (Mở được header) + 0.6 (Tỉ lệ trích xuất text thành công)
            return 0.4 + (0.6 * (success_pages / check_pages)) if check_pages > 0 else 0.5
    except Exception:
        return 0.0


def semantic_zip_integrity(file_path):
    try:
        if not zipfile.is_zipfile(file_path): return 0.0
        with zipfile.ZipFile(file_path, 'r') as zf:
            names = zf.namelist()
            if len(names) == 0: return 0.2
            if zf.testzip() is not None: return 0.3 # CRC failed (Partial Corruption)

            # Phân tích Semantic cho DOCX/XLSX/PPTX
            core_semantics = ['[Content_Types].xml', 'word/document.xml', 'xl/workbook.xml', 'ppt/presentation.xml']
            found_core = [f for f in core_semantics if f in names]

            if found_core:
                success = 0
                for cf in found_core:
                    try:
                        # Đọc thử lõi XML xem có bị mã hóa/hủy hoại không
                        data = zf.read(cf)
                        if b'<?xml' in data or b'<Types' in data or b'<w:document' in data:
                            success += 1
                    except Exception:
                        pass
                # Base 0.5 (ZIP hợp lệ) + 0.5 (Tỉ lệ đọc được lõi XML)
                return 0.5 + (0.5 * (success / len(found_core)))
                
        return 1.0 # ZIP thường, không có lõi Office, testzip OK
    except Exception:
        return 0.0


def semantic_image_integrity(file_path):
    try:
        # verify() chỉ check Header Marker
        img = Image.open(file_path)
        img.verify() 
        
        # load() ép thư viện giải mã toàn bộ Pixel Stream
        # Nếu Ransomware mã hóa Partial phần Data ảnh, load() sẽ crash!
        img2 = Image.open(file_path)
        img2.load() 
        return 1.0
    except Exception:
        return 0.0


def compute_semantic_integrity(file_path):
    ext = get_real_extension(file_path).lower()
    try:
        if ext == '.pdf': return semantic_pdf_integrity(file_path)
        elif ext in {'.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk', '.odt', '.ods', '.odp'}:
            return semantic_zip_integrity(file_path)
        elif ext in {'.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp'}:
            return semantic_image_integrity(file_path)
    except Exception:
        return 0.0
    return 0.5
# =========================================================
# ENTROPY BEHAVIOR ANALYSIS
# =========================================================

def analyze_entropy_behavior(
    block_entropies,
    features=None
):

    if not block_entropies:

        return {

            'behavior_type': 'Unknown',

            'behavior_score': 0.0,

            'signals': [],

            'entropy_profile': {}
        }

    arr = np.array(
        block_entropies,
        dtype=np.float64
    )

    entropy_mean = float(np.mean(arr))
    entropy_std = float(np.std(arr))
    entropy_min = float(np.min(arr))
    entropy_max = float(np.max(arr))

    entropy_range = entropy_max - entropy_min

    deltas = np.abs(np.diff(arr))

    delta_mean = (
        float(np.mean(deltas))
        if len(deltas)
        else 0.0
    )

    spike_count = int(
        np.sum(deltas > 1.0)
    )

    high_ratio = float(
        np.mean(arr > 7.2)
    )

    low_ratio = float(
        np.mean(arr < 6.0)
    )

    # =====================================================
    # INIT
    # =====================================================

    behavior = "Random / Unknown"

    score = 0.30

    signals = []

    # =====================================================
    # SAFE FEATURE EXTRACTION
    # =====================================================

    structural_damage = 0.0
    format_consistency = 1.0
    transition_count = 0

    if features:

        structural_damage = features.get(
            'structural_damage_score',
            0.0
        )

        format_consistency = features.get(
            'format_consistency_score',
            1.0
        )

        transition_count = features.get(
            'entropy_transition_count',
            0
        )

    # =====================================================
    # SAFE COMPRESSED CONTENT
    # =====================================================

    if (
        entropy_mean > 7.2
        and
        0.02 < entropy_std < 0.20
        and
        structural_damage < 0.10
        and
        format_consistency > 0.95
        and
        transition_count < 4
        and
        features.get('magic_header_score', 0.0) > 0.90
    ):

        behavior = "Safe Compressed Content"

        score = 0.15

        signals.append(
            "valid compressed container structure"
        )

    # =====================================================
    # UNIFORM ENCRYPTION
    # =====================================================

    elif (
        entropy_mean > 7.90
        and
        entropy_std < 0.02
    ):

        behavior = "Uniform Encryption"

        score = 0.95

        signals.append(
            "uniform high entropy across file"
        )

    # =====================================================
    # INTERMITTENT ENCRYPTION
    # =====================================================

    elif (
        entropy_std > 0.5
        and
        high_ratio > 0.10
        and
        low_ratio > 0.20
    ):

        behavior = "Intermittent Encryption"

        score = 0.90

        signals.append(
            "mixed plaintext/ciphertext regions"
        )

        signals.append(
            "high entropy fluctuation"
        )

    # =====================================================
    # PARTIAL ENCRYPTION
    # =====================================================

    elif (
        high_ratio > 0.10
        and
        high_ratio < 0.5
        and
        entropy_std > 0.25
    ):

        behavior = "Partial Encryption"

        score = 0.85

        signals.append(
            "localized encrypted regions"
        )

    # =====================================================
    # HEADER TAMPERING
    # =====================================================

    elif (
        entropy_mean < 6.2
        and
        entropy_max > 7.5
    ):

        behavior = "Header/Footer Tampering"

        score = 0.88

        signals.append(
            "localized entropy shock detected"
        )

        signals.append(
            "possible ransomware header encryption"
        )

    # =====================================================
    # PATTERN LEAKAGE
    # =====================================================

    elif (
        entropy_std < 0.05
        and
        6.2 < entropy_mean < 7.2
    ):

        behavior = "Pattern Leakage (Weak Crypto)"

        score = 0.85

        signals.append(
            "flat low entropy pattern"
        )

        signals.append(
            "possible XOR or ECB weakness"
        )

    # =====================================================
    # OBFUSCATION
    # =====================================================

    elif (
        entropy_mean > 6.0
        and
        entropy_std > 0.3
    ):

        behavior = "Obfuscation"

        score = 0.65

        signals.append(
            "non-uniform entropy distribution"
        )

    # =====================================================
    # SPIKES
    # =====================================================

    if spike_count > 8:

        score += 0.05

        signals.append(
            "multiple entropy spikes detected"
        )

    score = min(score, 1.0)

    return {

        'behavior_type': behavior,

        'behavior_score': float(score),

        'signals': signals,

        'entropy_profile': {

            'mean': entropy_mean,

            'std': entropy_std,

            'min': entropy_min,

            'max': entropy_max,

            'range': entropy_range,

            'delta_mean': delta_mean,

            'spike_count': spike_count,

            'high_entropy_ratio': high_ratio,

            'low_entropy_ratio': low_ratio
        }
    }

# =========================================================
# STAGE 1
# =========================================================

def run_stage1(
    file_path,
    model1,
    cols_s1
):

    data = read_sample_bytes(
        file_path
    )

    features = extract_all_features(
        data
    )

    X = extract_vector(
        features,
        cols_s1
    )

    probs = model1.predict_proba(
        X
    )[0]

    return {

        'prob_safe': float(
            probs[0]
        ),

        'prob_enc': float(
            probs[1]
        ),

        'features': features
    }

# =========================================================
# STAGE 2
# =========================================================

def run_stage2(
    file_path,
    file_size,
    model2,
    le2,
    cols_s2,
    global_features=None
):

    block_size = get_block_size(
        file_size
    )

    step_size = int(
        block_size *
        WINDOW_STEP_RATIO
    )

    predictions = []

    confidences = []

    block_entropies = []

    X_batch = []

    scan_len = min(
        file_size,
        GLOBAL_SCAN_LIMIT
    )

    with open(file_path, 'rb') as f:

        with mmap.mmap(
            f.fileno(),
            length=0,
            access=mmap.ACCESS_READ
        ) as mm:

            for offset in range(

                0,

                scan_len - block_size,

                step_size
            ):

                block = mm[
                    offset:
                    offset + block_size
                ]

                if (
                    len(block)
                    < block_size // 2
                ):
                    continue

                bf = extract_all_features(
                    block
                )

                entropy_value = bf.get(
                    'entropy',
                    0.0
                )

                block_entropies.append(
                    entropy_value
                )

                X = extract_vector(
                    bf,
                    cols_s2
                )

                X_batch.append(
                    X[0]
                )

    if not X_batch:

        return None

    # =====================================================
    # CONVERT TO NUMPY
    # =====================================================

    X_batch = np.array(
        X_batch,
        dtype=np.float32
    )

    # =====================================================
    # BATCH PREDICT
    # =====================================================

    preds = model2.predict(
        X_batch
    )

    probs = model2.predict_proba(
        X_batch
    )

    for i in range(len(preds)):

        conf = float(
            np.max(probs[i])
        )

        algo = (
            le2.inverse_transform(
                [preds[i]]
            )[0]
        )

        predictions.append(
            algo
        )

        confidences.append(
            conf
        )

    counter = Counter(
        predictions
    )

    distribution = {

        k: round(
            v / len(predictions),
            4
        )

        for k, v in counter.items()
    }

    behavior_analysis = (
        analyze_entropy_behavior(
            block_entropies,
            global_features
        )
    )


    dominant_algo = max(distribution, key=distribution.get) if distribution else None

    if dominant_algo == 'Pattern_Leakage' and distribution.get(dominant_algo, 0) > 0.4:
        behavior_analysis['behavior_type'] = "Pattern Leakage (Weak Crypto)"
        behavior_analysis['behavior_score'] = max(0.90, behavior_analysis.get('behavior_score', 0.0))
        behavior_analysis['signals'].append("cryptographic pattern leakage (weak cipher / ECB)")

    elif dominant_algo == 'Obfuscation_Base64' and distribution.get(dominant_algo, 0) > 0.5:
        behavior_analysis['behavior_type'] = "Base64 Obfuscation"
        behavior_analysis['behavior_score'] = max(0.85, behavior_analysis.get('behavior_score', 0.0))

    return {

        'behavior_type':

            behavior_analysis[
                'behavior_type'
            ],

        'behavior_score':

            behavior_analysis.get(
                'behavior_score',
                behavior_analysis.get(
                    'risk_level',
                    0.0
                )
            ),

        'signals':

            behavior_analysis[
                'signals'
            ],

        'entropy_profile':

            behavior_analysis[
                'entropy_profile'
            ],

        'algorithm_distribution':

            distribution,

        'avg_confidence': float(
            np.mean(confidences)
        ),

        'block_size':
            block_size,

        'total_blocks':
            len(predictions),

        'entropy_sequence': [

            round(v, 4)

            for v in block_entropies
        ]
    }

# =========================================================
# FUSION RISK ENGINE
# =========================================================

def compute_fusion_risk(
    stage1,
    stage2,
    file_path
):

    features = stage1['features']

    ext = get_real_extension(file_path)

    # =====================================================
    # RANSOMWARE EXTENSION EARLY DETECTION
    # =====================================================

    is_ransomware_ext = (
        ext in RANSOMWARE_EXTENSIONS
    )

    p_ai = stage1['prob_enc']

    behavior = (
        stage2['behavior_score']
        if stage2 else 0.0
    )

    # =====================================================
    # TRANSITION SCORE
    # =====================================================

    transition_count = features.get(
        'entropy_transition_count',
        0
    )

    transition_score = min(
        transition_count / 10.0,
        1.0
    )

    # =====================================================
    # STRUCTURAL
    # =====================================================

    structural = float(np.mean([

        features.get(
            'structural_damage_score',
            0.0
        ),

        1.0 - features.get(
            'format_consistency_score',
            1.0
        ),

        transition_score
    ]))

    # =====================================================
    # ANOMALY
    # =====================================================

    anomaly = float(np.mean([

        features.get(
            'semantic_anomaly_score',
            0.0
        ),

        features.get(
            'flat_entropy_score',
            0.0
        )
    ]))

    # =====================================================
    # SURVIVABILITY
    # =====================================================

    survivability = compute_semantic_integrity(
        file_path
    )

    # =====================================================
    # BASE RISK
    # =====================================================

    risk = (

        W_AI * p_ai +

        W_BEHAVIOR * behavior +

        W_STRUCTURAL * structural +

        W_ANOMALY * anomaly -

        W_SURVIVABILITY * survivability
    )

    # =====================================================
    # SAFE COMPRESSED OVERRIDE
    # =====================================================

    is_flat_high = (
        features.get(
            'flat_entropy_score',
            0.0
        ) > 0.8
    )

    # =====================================================
    # FILE-FORMAT-AWARE SAFE LOGIC
    # =====================================================

    SAFE_FORMATS = {
        '.pdf',
        '.docx',
        '.xlsx',
        '.pptx',
        '.zip',
        '.rar',
        '.7z',
        '.jpg',
        '.png',
        '.mp4',
        '.mp3'
    }

    magic_header = features.get(
        'magic_header_score',
        0.0
    )

    structural_damage = features.get(
        'structural_damage_score',
        0.0
    )

    format_consistency = features.get(
        'format_consistency_score',
        1.0
    )

    is_struct_ok = (
        structural_damage < 0.15
    )

    # File hợp lệ + đúng magic bytes
    # => giảm mạnh risk false positive

    if (
        ext in SAFE_FORMATS
        and magic_header > 0.95
        and structural_damage < 0.10
        and format_consistency > 0.90
        and not is_ransomware_ext
    ):

        risk *= 0.25

        logger.info(
            f"SAFE FORMAT DETECTED: {ext}"
        )


        is_high_entropy = (
            features.get(
                'entropy_mean',
                0.0
            ) > 7.4
        )

    
    suspicious_exts = ['.locked', '.enc', '.encrypted', '.bin', '.ransom', '.ryk', '.lockbit']
    is_sus_ext = ext in suspicious_exts

    SAFE_COMPRESSED_EXTS = {
        '.pdf',
        '.docx',
        '.xlsx',
        '.pptx',
        '.zip',
        '.rar',
        '.7z',
        '.png',
        '.jpg',
        '.jpeg',
        '.mp3',
        '.mp4',
        '.avi',
        '.mov',
        '.wmv',
        '.apk',
        '.jar',
        '.epub',
        '.odt',
        '.ods',
        '.odp'
    }

    format_ok = (
        features.get(
            'format_consistency_score',
            1.0
        ) > 0.95
    )

    entropy_std = features.get(
        'entropy_std',
        1.0
    )

    transition_count = features.get(
        'entropy_transition_count',
        0
    )

    is_safe_compressed = (
        ext in SAFE_COMPRESSED_EXTS
        and is_struct_ok
        and format_ok
        and entropy_std < 0.25
        and transition_count < 5
        and features.get('magic_header_score', 0.0) > 0.90
        and features.get('structural_damage_score', 0.0) < 0.08
        and features.get('semantic_anomaly_score', 0.0) < 0.15
        and features.get('entropy_mean', 0.0) < 7.85
        and not is_ransomware_ext
    )

    if (is_safe_compressed and features.get('entropy_mean', 0.0) < 7.85):

        if stage2:
            stage2['behavior_score'] *= 0.35

        if not is_sus_ext:

            risk *= 0.45

            if stage2:
                stage2['behavior_type'] = (
                    "Safe Compressed Document"
                )

                stage2['signals'].append(
                    "safe compressed container signature"
                )

    # =====================================================
    # LOW FLAT WEAK CRYPTO
    # =====================================================

    is_flat_low = (
        features.get(
            'entropy_std',
            1.0
        ) < 0.1
    )

    is_low_entropy = (
        features.get(
            'entropy_mean',
            8.0
        ) < 6.0
    )

    SAFE_TEXT_EXTS = {
    '.txt',
    '.log',
    '.csv',
    '.json',
    '.xml',
    '.md',
    '.ini'
    }

    if (
        is_flat_low
        and
        is_low_entropy
        and ext not in SAFE_TEXT_EXTS
    ):

        if (
            stage2
            and
            stage2.get(
                'behavior_type'
            ) == "Pattern Leakage (Weak Crypto)"
        ):

            risk = max(risk, 0.85)

            logger.warning(
                "Weak Crypto Pattern Leakage"
            )
    
    # =====================================================
    # HARD STRUCTURAL SAFE OVERRIDE
    # =====================================================

    if survivability >= 0.95 and not is_ransomware_ext:

        if ext in {
            '.pdf',
            '.zip',
            '.docx',
            '.xlsx',
            '.pptx',
            '.jpg',
            '.jpeg',
            '.png'
        }:

            if (
                features.get('structural_damage_score', 0.0) < 0.10
                and
                features.get('format_consistency_score', 1.0) > 0.90
            ):

                logger.info(
                    f"SURVIVABILITY SAFE OVERRIDE: {file_path}"
                )

                risk *= 0.15

    # =====================================================
    # PARTIAL ENCRYPTION RECOVERY
    # =====================================================

    if survivability >= 0.90:

        if stage2:

            if stage2['behavior_type'] in {

                "Partial Encryption",

                "Intermittent Encryption",

                "Header/Footer Tampering"

            }:

                if features.get(
                    'entropy_transition_count',
                    0
                ) > 6:

                    risk = max(risk, 0.75)

                    logger.warning(
                        "PARTIAL ENCRYPTION DETECTED "
                        "DESPITE STRUCTURAL SURVIVAL"
                    )

    # =====================================================
    # FINAL CLAMP
    # =====================================================

    # =====================================================
    # RANSOMWARE EXT FLOOR
    # =====================================================

    if is_ransomware_ext:
        # Files with known ransomware extensions should
        # never be classified as safe
        risk = max(risk, 0.75)

        logger.warning(
            f"RANSOMWARE EXT DETECTED: {ext} => "
            f"risk floor applied"
        )

    risk = max(
        0.0,
        min(risk, 1.0)
    )

    return float(risk)

# =========================================================
# EVIDENCE ENGINE
# =========================================================

def build_evidence(
    stage1,
    stage2,
    file_path
):

    evidence = []

    features = stage1['features']

    semantic_integrity = compute_semantic_integrity(file_path)

    # =====================================================
    # STRUCTURAL DAMAGE
    # =====================================================

    structural_damage = features.get(
        'structural_damage_score',
        0.0
    )

    if structural_damage > 0.5:

        evidence.append({

            'type': 'structural',

            'severity': 'high',

            'description':
                'severe file structure corruption'
        })
    # =====================================================
    # FORMAT CONSISTENCY
    # =====================================================

    consistency = features.get(
        'format_consistency_score',
        1.0
    )

    if consistency < 0.4:

        evidence.append({

            'type': 'format',

            'severity': 'medium',

            'description':
                'file format inconsistency detected'
        })

    # =====================================================
    # SEMANTIC ANOMALY
    # =====================================================

    semantic = features.get(
        'semantic_anomaly_score',
        0.0
    )

    if semantic > 0.5:

        evidence.append({

            'type': 'semantic',

            'severity': 'high',

            'description':
                'semantic content anomaly detected'
        })

    # =====================================================
    # FLAT ENTROPY
    # =====================================================

    flat_entropy = features.get(
        'flat_entropy_score',
        0.0
    )

    if flat_entropy > 0.7:

        evidence.append({

            'type': 'entropy',

            'severity': 'high',

            'description':
                'uniform entropy pattern detected'
        })

    # =====================================================
    # ENTROPY TRANSITIONS
    # =====================================================

    transition_count = features.get(
        'entropy_transition_count',
        0
    )

    if transition_count > 5:

        evidence.append({

            'type': 'transition',

            'severity': 'high',

            'description':

                f'abnormal entropy transitions '
                f'({transition_count} times)'
        })
    
    # =====================================================
    # SURVIVABILITY
    # =====================================================

    if semantic_integrity >= 0.80:
        evidence.append({'type': 'semantic', 'severity': 'low', 'description': 'core semantic content successfully recovered'})
    elif semantic_integrity <= 0.40:
        evidence.append({'type': 'semantic', 'severity': 'high', 'description': 'semantic content destroyed (partial/full corruption)'})
    
    # =====================================================
    # PATTERN LEAKAGE / ECB MODE
    # =====================================================
    block_repeat = features.get('block_repeat_score', 0.0)
    
    if block_repeat > 0.4:
        evidence.append({
            'type': 'pattern',
            'severity': 'high',
            'description': f'high block repetition ({block_repeat*100:.1f}%), possible ECB mode leakage'
        })

    # =====================================================
    # STAGE 2 SIGNALS
    # =====================================================

    if stage2:

        for signal in stage2.get(
            'signals',
            []
        ):

            evidence.append({

                'type': 'behavior',

                'severity': 'medium',

                'description': signal
            })

    return evidence

# =========================================================
# MAIN DETECTOR
# =========================================================

def detect_file(

    file_path,

    model1,

    model2,

    le2,

    cols_s1,

    cols_s2
):

    if not os.path.exists(file_path):

        return {

            'error':
                f'File not found: {file_path}'
        }

    file_size = os.path.getsize(
        file_path
    )
    ext = get_real_extension(file_path)

    # =====================================================
    # SAFETY NET
    # =====================================================

    if file_size < MIN_FILE_SIZE:

        return {

            'file':
                os.path.basename(file_path),

            'size':
                file_size,

            'status':
                'IGNORED_SMALL_FILE'
        }

    if file_size > MAX_FILE_SIZE:

        return {

            'file':
                os.path.basename(file_path),

            'size':
                file_size,

            'status':
                'IGNORED_TOO_LARGE'
        }

    # =====================================================
    # STAGE 1
    # =====================================================

    stage1 = run_stage1(

        file_path,

        model1,

        cols_s1
    )

    print("\n===== DEBUG FEATURES =====")
    print(file_path)
    print(stage1['features'])
    print("==========================\n")

    # =====================================================
    # STAGE 2
    # =====================================================

    stage2 = None

    if file_size >= 512:

        stage2 = run_stage2(

            file_path,

            file_size,

            model2,

            le2,

            cols_s2,

            stage1['features']
        )

    # =====================================================
    # FUSION RISK
    # =====================================================

    risk_score = compute_fusion_risk(

        stage1,

        stage2,

        file_path
    )

    # =====================================================
    # ENCRYPTED DECISION
    # =====================================================

    encrypted = (
        risk_score >= ENCRYPTION_THRESHOLD
    )

    # =====================================================
    # SMART OVERRIDE
    # =====================================================

    if not encrypted and stage2:

        ext = get_real_extension(file_path)

        SAFE_OVERRIDE_EXEMPT = {
            '.pdf',
            '.zip',
            '.rar',
            '.7z',
            '.docx',
            '.xlsx',
            '.pptx',
            '.png',
            '.jpg',
            '.jpeg',
            '.mp3',
            '.mp4',
            '.avi',
            '.mov'
        }

        suspicious = [
            "Uniform Encryption",
            "Intermittent Encryption",
            "Partial Encryption",
            "Obfuscation",
            "Base64 Obfuscation",
            "Header/Footer Tampering",
            "Header Tampering"
        ]

        struct_damage = stage1['features'].get(
            'structural_damage_score',
            0.0
        )

        format_score = stage1['features'].get(
            'format_consistency_score',
            1.0
        )

        entropy_std = stage1['features'].get(
            'entropy_std',
            1.0
        )

        transition_count = stage1['features'].get(
            'entropy_transition_count',
            0
        )

        # =====================================================
        # TRUSTED COMPRESSED FILE
        # =====================================================

        is_ransom_ext = (
            ext in RANSOMWARE_EXTENSIONS
        )

        trusted_compressed = (

            ext in SAFE_OVERRIDE_EXEMPT
            and struct_damage < 0.15
            and format_score > 0.90
            and entropy_std < 0.50
            and transition_count < 6
            and not is_ransom_ext
        )

        # =====================================================
        # ONLY OVERRIDE NON-TRUSTED FILES
        # =====================================================

        if (
            not trusted_compressed
            and
            struct_damage > 0.30
            and
            stage2['behavior_type'] in suspicious
            and
            stage2['behavior_score'] >= OVERRIDE_THRESHOLD
        ):

            encrypted = True

            logger.warning(
                "SMART OVERRIDE TRIGGERED: "
                f"{os.path.basename(file_path)}"
            )

    # =====================================================
    # BEHAVIOR TYPE
    # =====================================================

    if encrypted:

        if stage2:

            behavior_type = stage2[
                'behavior_type'
            ]

        else:

            behavior_type = (
                "Encrypted Content"
            )

    else:

        behavior_type = (
            "Safe / Benign"
        )

    # =====================================================
    # EVIDENCE
    # =====================================================

    evidence = build_evidence(
        stage1,
        stage2,
        file_path
    )

    # =====================================================
    # SURVIVABILITY
    # =====================================================

    survivability = compute_semantic_integrity(
        file_path
    )

    if survivability > 0.95:

        evidence.append({

            'type': 'survivability',

            'severity': 'low',

            'description':
                'file structure fully recoverable / parsable'
        })

    # =====================================================
    # RESULT (SỬA Ở ĐÂY 👇)
    # =====================================================

    features = stage1['features'] # Lấy features để xuất điểm breakdown

    result = {

        'file': os.path.basename(file_path),
        'size': file_size,
        'encrypted': encrypted,

        # GUI COMPATIBLE
        'risk_level': round(risk_score, 4),
        'behavior_type': behavior_type,
        'prob_safe': round(stage1['prob_safe'], 4),
        'prob_enc': round(stage1['prob_enc'], 4),
        'evidence': evidence,

        # 👇 BỔ SUNG KHỐI NÀY ĐỂ GIAO DIỆN HIỆN BẢNG RISK BREAKDOWN 👇
        'risk_breakdown': {
            'ai_risk': float(stage1['prob_enc']),
            'behavior_score': float(stage2['behavior_score']) if stage2 else 0.0,
            'structural_damage': float(features.get('structural_damage_score', 0.0)),
            'semantic_anomaly': float(features.get('semantic_anomaly_score', 0.0)),
            'survivability_score': float(compute_semantic_integrity(file_path)),
            'final_risk': float(risk_score)
        },
        # 👆 ===================================================== 👆

        'entropy_profile': stage2['entropy_profile'] if stage2 else {},
        
        # ... (các phần bên dưới giữ nguyên)
        'algorithm_distribution': stage2['algorithm_distribution'] if stage2 else {},
        'avg_confidence': stage2['avg_confidence'] if stage2 else stage1['prob_enc'],
        'block_size': stage2['block_size'] if stage2 else file_size,
        'total_blocks': stage2['total_blocks'] if stage2 else 1,
        'entropy_sequence': stage2['entropy_sequence'] if stage2 else []
    }

    return result

# =========================================================
# DIRECTORY SCAN
# =========================================================

def scan_directory(directory):

    (

        model1,

        model2,

        le2,

        cols_s1,

        cols_s2

    ) = load_models()

    results = []

    for root, _, files in os.walk(directory):

        for file in files:

            path = os.path.join(
                root,
                file
            )

            try:

                result = detect_file(

                    path,

                    model1,

                    model2,

                    le2,

                    cols_s1,

                    cols_s2
                )

                results.append(
                    result
                )

            except Exception as e:

                logger.error(
                    f"{path}: {e}"
                )

                results.append({

                    'file': file,

                    'error': str(e)
                })

    return results

# =========================================================
# PRINT RESULT
# =========================================================

def print_result(r):

    print("\n" + "=" * 80)

    if 'error' in r:

        print(
            f"❌ ERROR: {r['error']}"
        )

        return

    print(
        f"📄 File: {r['file']}"
    )

    print(
        f"📦 Size: {r['size']:,} bytes"
    )

    print(
        f"🧠 Risk Level: {r['risk_level']:.4f}"
    )

    print(
        f"🔍 Behavior: {r['behavior_type']}"
    )

    if r['encrypted']:

        print(
            "🔒 STATUS: ENCRYPTED / SUSPICIOUS"
        )

    else:

        print(
            "✅ STATUS: SAFE / BENIGN"
        )

    print("\nEvidence:")

    for e in r.get(
        'evidence',
        []
    ):

        print(

            f"  [{e['severity'].upper()}] "

            f"{e['type']} -> "

            f"{e['description']}"
        )

    print("=" * 80)

# =========================================================
# MAIN
# =========================================================

if __name__ == '__main__':

    parser = argparse.ArgumentParser(

        description=
            'AI Encryption Detector V11'
    )

    parser.add_argument(
        '--file',
        type=str
    )

    parser.add_argument(
        '--dir',
        type=str
    )

    args = parser.parse_args()

    (

        model1,

        model2,

        le2,

        cols_s1,

        cols_s2

    ) = load_models()

    # =====================================================
    # SINGLE FILE
    # =====================================================

    if args.file:

        result = detect_file(

            args.file,

            model1,

            model2,

            le2,

            cols_s1,

            cols_s2
        )

        print_result(result)

    # =====================================================
    # DIRECTORY
    # =====================================================

    elif args.dir:

        results = scan_directory(
            args.dir
        )

        for r in results:

            print_result(r)

    else:

        parser.print_help()