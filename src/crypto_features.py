"""
Research-Grade Crypto Feature Extraction Engine (FINAL V10)
==========================================================

Major Improvements:
-------------------
1. Structural Integrity Analysis
2. Semantic File Identity
3. Entropy Gradient Analysis
4. Entropy Shock Detection
5. Flat Entropy Detection
6. Evidence Fusion Features
7. Better False Positive Reduction
8. Behavioral Ransomware Profiling
"""

import os
import math
import mmap
import zlib
import struct
import numpy as np

from numpy.fft import fft
from collections import Counter

from src.utils import setup_logger

logger = setup_logger(
    'crypto_features',
    'logs/crypto_features.log'
)

# ============================================================
# CONSTANTS
# ============================================================

COMPRESSION_SAMPLE_SIZE = 1024 * 1024

MAX_ANALYSIS_SIZE = 8 * 1024 * 1024

DEFAULT_WINDOW_SIZE = 4096
DEFAULT_STEP_SIZE = 2048

# ============================================================
# MAGIC HEADERS
# ============================================================

KNOWN_HEADERS = {

    b'PK\x03\x04': 'ZIP',

    b'\x1f\x8b': 'GZIP',

    b'\xff\xd8\xff': 'JPEG',

    b'%PDF': 'PDF',

    b'7z\xbc\xaf': '7ZIP',

    b'Rar!': 'RAR',

    b'\x89PNG\r\n\x1a\n': 'PNG',

    b'ID3': 'MP3',
}

# ============================================================
# FILE FORMAT HELPERS
# ============================================================

def identify_file_format(data):

    if len(data) < 16:
        return "UNKNOWN"

    for sig, name in KNOWN_HEADERS.items():

        if data.startswith(sig):
            return name

    if b'ftyp' in data[:64]:
        return "MP4"

    return "UNKNOWN"

# ============================================================
# MEMORY SAFE FILE LOADING
# ============================================================

def load_file_sample(
    file_path,
    max_size=MAX_ANALYSIS_SIZE
):

    try:

        file_size = os.path.getsize(file_path)

        read_size = min(file_size, max_size)

        with open(file_path, 'rb') as f:

            with mmap.mmap(
                f.fileno(),
                length=0,
                access=mmap.ACCESS_READ
            ) as mm:

                data = mm[:read_size]

        return data

    except Exception as e:

        logger.error(
            f"mmap read failed: {file_path} | {e}"
        )

        return b''

# ============================================================
# SHANNON ENTROPY
# ============================================================

def calculate_shannon_entropy(data):

    if not data:
        return 0.0

    counts = Counter(data)

    length = len(data)

    entropy = 0.0

    for count in counts.values():

        p = count / length

        entropy -= p * math.log2(p)

    return float(entropy)

# ============================================================
# BYTE STATISTICS
# ============================================================

def calculate_byte_statistics(data):

    if not data:

        return {
            "mean": 0.0,
            "std_dev": 0.0,
            "variance": 0.0,
            "skewness": 0.0,
            "kurtosis": 0.0,
            "median": 0.0
        }

    arr = np.frombuffer(
        data,
        dtype=np.uint8
    ).astype(np.float64)

    mean = np.mean(arr)

    std_dev = np.std(arr)

    variance = np.var(arr)

    median = np.median(arr)

    if std_dev > 0:

        skewness = np.mean(
            ((arr - mean) / std_dev) ** 3
        )

        kurtosis = (
            np.mean(
                ((arr - mean) / std_dev) ** 4
            ) - 3.0
        )

    else:

        skewness = 0.0
        kurtosis = 0.0

    return {

        "mean": float(mean),

        "std_dev": float(std_dev),

        "variance": float(variance),

        "skewness": float(skewness),

        "kurtosis": float(kurtosis),

        "median": float(median),
    }

# ============================================================
# CHI SQUARE
# ============================================================

def calculate_chi_square(data):

    if not data:
        return 0.0

    n = len(data)

    expected = n / 256.0

    counts = Counter(data)

    chi_sq = 0.0

    for b in range(256):

        observed = counts.get(b, 0)

        chi_sq += (
            (observed - expected) ** 2
        ) / expected

    return float(chi_sq / n)

# ============================================================
# COMPRESSION RATIO
# ============================================================

def calculate_compression_ratio(data):

    if not data:
        return 1.0

    try:

        sample = data[:COMPRESSION_SAMPLE_SIZE]

        compressed = zlib.compress(
            sample,
            level=9
        )

        ratio = len(compressed) / len(sample)

        return float(ratio)

    except Exception:

        return 1.0

# ============================================================
# ASCII PROFILE
# ============================================================

def calculate_ascii_profile(data):

    if not data:

        return {

            "ascii_ratio": 0.0,

            "base64_charset_ratio": 0.0
        }

    printable = sum(
        1 for b in data
        if 32 <= b <= 126
    )

    ascii_ratio = printable / len(data)

    base64_chars = (
        b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        b'abcdefghijklmnopqrstuvwxyz'
        b'0123456789+/='
    )

    base64_count = sum(
        1 for b in data
        if b in base64_chars
    )

    base64_ratio = base64_count / len(data)

    return {

        "ascii_ratio": float(ascii_ratio),

        "base64_charset_ratio": float(base64_ratio)
    }

# ============================================================
# MAGIC HEADER SCORE
# ============================================================

def calculate_magic_header_score(data):

    if len(data) < 8:
        return 0.0

    for sig in KNOWN_HEADERS:

        if data.startswith(sig):
            return 1.0

    return 0.0

# ============================================================
# BLOCK REPEAT SCORE
# ============================================================

def calculate_block_repeat_score(
    data,
    block_size=16
):

    if len(data) < block_size * 2:
        return 0.0

    blocks = [

        data[i:i + block_size]

        for i in range(
            0,
            len(data),
            block_size
        )
    ]

    total = len(blocks)

    unique = len(set(blocks))

    repeat_ratio = 1.0 - (
        unique / total
    )

    return float(repeat_ratio)

# ============================================================
# ENTROPY PROFILE
# ============================================================

def calculate_entropy_profile_features(
    data,
    window_size=4096,
    step=2048
):

    if len(data) < window_size:

        return _empty_entropy_profile()

    entropies = []

    for i in range(
        0,
        len(data) - window_size,
        step
    ):

        chunk = data[
            i:i + window_size
        ]

        entropies.append(
            calculate_shannon_entropy(chunk)
        )

    if not entropies:
        return _empty_entropy_profile()

    entropies = np.array(
        entropies,
        dtype=np.float64
    )

    entropy_mean = np.mean(entropies)

    entropy_std = np.std(entropies)

    entropy_range = (
        np.max(entropies) -
        np.min(entropies)
    )

    high_entropy_ratio = np.mean(
        entropies > 7.5
    )

    low_entropy_ratio = np.mean(
        entropies < 5.5
    )

    # ========================================================
    # ENTROPY DELTAS
    # ========================================================

    deltas = np.abs(
        np.diff(entropies)
    )

    entropy_delta_mean = 0.0
    entropy_delta_std = 0.0
    entropy_transition_count = 0
    entropy_shock_score = 0.0

    if len(deltas) > 0:

        entropy_delta_mean = np.mean(deltas)

        entropy_delta_std = np.std(deltas)

        entropy_transition_count = np.sum(
            deltas > 0.8
        )

        entropy_shock_score = np.max(deltas)

    # ========================================================
    # SPIKE COUNT
    # ========================================================

    entropy_spike_count = np.sum(
        deltas > 1.0
    )

    # ========================================================
    # PERIODICITY
    # ========================================================

    entropy_periodicity = 0.0

    if len(entropies) >= 8:

        centered = (
            entropies - np.mean(entropies)
        )

        spectrum = np.abs(
            fft(centered)
        )

        spectrum = spectrum[
            1:len(spectrum)//2
        ]

        if len(spectrum) > 0:

            dominant_power = np.max(spectrum)

            total_power = np.sum(spectrum)

            if total_power > 0:

                entropy_periodicity = (
                    dominant_power /
                    total_power
                )

    # ========================================================
    # FLAT ENTROPY DETECTION
    # ========================================================

    flat_entropy_score = 0.0

    if entropy_mean > 7.5 and entropy_std < 0.05:

        flat_entropy_score = 1.0

    return {

        "entropy_mean": float(entropy_mean),

        "entropy_std": float(entropy_std),

        "entropy_min": float(np.min(entropies)),

        "entropy_max": float(np.max(entropies)),

        "entropy_range": float(entropy_range),

        "high_entropy_ratio": float(high_entropy_ratio),

        "low_entropy_ratio": float(low_entropy_ratio),

        "entropy_spike_count": int(entropy_spike_count),

        "entropy_periodicity": float(entropy_periodicity),

        "entropy_delta_mean": float(entropy_delta_mean),

        "entropy_delta_std": float(entropy_delta_std),

        "entropy_transition_count": int(entropy_transition_count),

        "entropy_shock_score": float(entropy_shock_score),

        "flat_entropy_score": float(flat_entropy_score),

        "entropy_sequence": entropies.tolist()
    }

# ============================================================
# STRUCTURAL INTEGRITY (V12 Optimized)
# ============================================================

def analyze_structural_integrity(
    data,
    file_format
):

    damage_score = 0.0

    # ========================================================
    # FILE TRUNCATION DETECTION
    # ========================================================

    is_truncated = (

        len(data)

        >=

        (4 * 1024 * 1024)
    )

    try:

        # ====================================================
        # PNG
        # ====================================================

        if file_format == "PNG":

            if not data.startswith(
                b'\x89PNG\r\n\x1a\n'
            ):

                damage_score += 0.5

            # IHDR luôn nằm đầu file
            if b'IHDR' not in data[:1024]:

                damage_score += 0.2

            if b'IDAT' not in data:

                damage_score += 0.4

            # =================================================
            # CHỈ CHECK IEND NẾU FILE ĐƯỢC ĐỌC FULL
            # =================================================

            if (

                not is_truncated

                and

                b'IEND' not in data[-2048:]
            ):

                damage_score += 0.3

        # ====================================================
        # PDF
        # ====================================================

        elif file_format == "PDF":

            if not data.startswith(
                b'%PDF'
            ):

                damage_score += 0.5

            # =================================================
            # CHỈ CHECK %%EOF NẾU FILE ĐƯỢC ĐỌC FULL
            # =================================================

            if (

                not is_truncated

                and

                b'%%EOF' not in data[-2048:]
            ):

                damage_score += 0.5

        # ====================================================
        # ZIP / DOCX / XLSX / PPTX / LAB
        # ====================================================

        elif file_format == "ZIP":

            if not data.startswith(
                b'PK'
            ):

                damage_score += 0.5

            # =================================================
            # OFFICE STRUCTURE
            # =================================================

            if (

                b'word/' not in data

                and

                b'xl/' not in data

                and

                b'ppt/' not in data
            ):

                # ZIP thường hoặc LAB
                damage_score += 0.1

        # ====================================================
        # GENERIC UNKNOWN FORMAT
        # ====================================================

        else:

            # Không phạt mạnh file lạ
            damage_score += 0.0

        return min(
            damage_score,
            1.0
        )

    except Exception:

        return 1.0

        
# ============================================================
# SEMANTIC ANOMALY
# ============================================================

def calculate_semantic_anomaly(
    file_format,
    features
):

    score = 0.0

    entropy_std = features.get(
        "entropy_std", 0
    )

    entropy_shock = features.get(
        "entropy_shock_score", 0
    )

    structural_damage = features.get(
        "structural_damage_score", 0
    )

    if file_format in [
        "PNG",
        "PDF",
        "ZIP",
        "JPEG",
        "MP4"
    ]:

        if entropy_std > 0.4:
            score += 0.4

        if entropy_shock > 1.5:
            score += 0.4

        if structural_damage > 0.4:
            score += 0.4

    return min(score, 1.0)

# ============================================================
# RANSOMWARE SCORE
# ============================================================

def calculate_ransomware_score(features):

    score = 0.0

    if features.get(
        "entropy_range", 0
    ) > 2.0:

        score += 2.0

    if features.get(
        "entropy_spike_count", 0
    ) > 5:

        score += 2.0

    if features.get(
        "entropy_transition_count", 0
    ) > 5:

        score += 2.0

    if features.get(
        "entropy_shock_score", 0
    ) > 1.5:

        score += 2.0

    if (
        features.get(
            "high_entropy_ratio", 0
        ) > 0.3

        and

        features.get(
            "low_entropy_ratio", 0
        ) > 0.2
    ):

        score += 3.0

    if features.get(
        "structural_damage_score", 0
    ) > 0.5:

        score += 3.0

    return float(score)

# ============================================================
# FULL FEATURE EXTRACTION
# ============================================================

def extract_all_features(
    file_path_or_bytes
):

    if isinstance(
        file_path_or_bytes,
        str
    ):

        data = load_file_sample(
            file_path_or_bytes
        )

    else:

        data = file_path_or_bytes

    if not data:
        return _empty_features()

    features = {}

    # ========================================================
    # BASIC
    # ========================================================

    features['entropy'] = (
        calculate_shannon_entropy(data)
    )

    features.update(
        calculate_byte_statistics(data)
    )

    features['chi_square'] = (
        calculate_chi_square(data)
    )

    features['compression_ratio'] = (
        calculate_compression_ratio(data)
    )

    features.update(
        calculate_ascii_profile(data)
    )

    features['magic_header_score'] = (
        calculate_magic_header_score(data)
    )

    features['block_repeat_score'] = (
        calculate_block_repeat_score(data)
    )

    # ========================================================
    # FORMAT IDENTITY
    # ========================================================

    file_format = identify_file_format(data)

    features['detected_format'] = file_format

    filename = ""
    if isinstance(file_path_or_bytes, str):
        filename = os.path.basename(file_path_or_bytes).lower()

    header_destroyed = False
    if filename:
        ext_map = ['.pdf', '.png', '.jpg', '.jpeg', '.zip', '.docx', '.xlsx', '.pptx']
        if any(ext in filename for ext in ext_map) and file_format == 'UNKNOWN':
            header_destroyed = True

    # ========================================================
    # ENTROPY PROFILE
    # ========================================================

    entropy_features = (
        calculate_entropy_profile_features(data)
    )

    features.update(entropy_features)

    # ========================================================
    # STRUCTURAL DAMAGE
    # ========================================================

    structural_damage = (
        analyze_structural_integrity(
            data,
            file_format
        )
    )

    if header_destroyed:
        structural_damage = 1.0

    features[
        'structural_damage_score'
    ] = structural_damage

    # ========================================================
    # SEMANTIC ANOMALY
    # ========================================================

    semantic_score = (
        calculate_semantic_anomaly(
            file_format,
            features
        )
    )

    features[
        'semantic_anomaly_score'
    ] = semantic_score

    # ========================================================
    # FORMAT CONSISTENCY
    # ========================================================

    consistency = 1.0 - (
        structural_damage * 0.6 +
        semantic_score * 0.4
    )

    consistency = max(
        0.0,
        min(consistency, 1.0)
    )

    features[
        'format_consistency_score'
    ] = consistency

    # ========================================================
    # FILE SIZE
    # ========================================================

    features['file_size'] = len(data)

    # ========================================================
    # RANSOMWARE SCORE
    # ========================================================

    features['ransomware_score'] = (
        calculate_ransomware_score(features)
    )

    return features

# ============================================================
# BLOCK FEATURES
# ============================================================

def extract_block_features(
    data,
    block_size=4096
):

    if not data:
        return []

    blocks = []

    for offset in range(
        0,
        len(data),
        block_size
    ):

        block = data[
            offset:offset + block_size
        ]

        if len(block) < block_size // 2:
            continue

        features = extract_all_features(
            block
        )

        features['block_offset'] = offset

        features['block_size'] = len(block)

        blocks.append(features)

    return blocks

# ============================================================
# EMPTY FEATURES
# ============================================================

def _empty_entropy_profile():

    return {

        "entropy_mean": 0.0,

        "entropy_std": 0.0,

        "entropy_min": 0.0,

        "entropy_max": 0.0,

        "entropy_range": 0.0,

        "high_entropy_ratio": 0.0,

        "low_entropy_ratio": 0.0,

        "entropy_spike_count": 0,

        "entropy_periodicity": 0.0,

        "entropy_delta_mean": 0.0,

        "entropy_delta_std": 0.0,

        "entropy_transition_count": 0,

        "entropy_shock_score": 0.0,

        "flat_entropy_score": 0.0,

        "entropy_sequence": []
    }

def _empty_features():

    features = {

        'entropy': 0.0,

        'mean': 0.0,

        'std_dev': 0.0,

        'variance': 0.0,

        'skewness': 0.0,

        'kurtosis': 0.0,

        'median': 0.0,

        'chi_square': 0.0,

        'compression_ratio': 0.0,

        'ascii_ratio': 0.0,

        'base64_charset_ratio': 0.0,

        'magic_header_score': 0.0,

        'block_repeat_score': 0.0,

        'detected_format': 'UNKNOWN',

        'structural_damage_score': 0.0,

        'semantic_anomaly_score': 0.0,

        'format_consistency_score': 1.0,

        'ransomware_score': 0.0,

        'file_size': 0,
    }

    features.update(
        _empty_entropy_profile()
    )

    return features

# ============================================================
# FEATURE COLUMNS
# ============================================================

FEATURE_COLUMNS = [

    'entropy',

    'mean',
    'std_dev',
    'variance',
    'skewness',
    'kurtosis',
    'median',

    'chi_square',

    'compression_ratio',

    'ascii_ratio',

    'base64_charset_ratio',

    'magic_header_score',

    'block_repeat_score',

    'entropy_mean',

    'entropy_std',

    'entropy_min',

    'entropy_max',

    'entropy_range',

    'high_entropy_ratio',

    'low_entropy_ratio',

    'entropy_spike_count',

    'entropy_periodicity',

    'entropy_delta_mean',

    'entropy_delta_std',

    'entropy_transition_count',

    'entropy_shock_score',

    'flat_entropy_score',

    'structural_damage_score',

    'semantic_anomaly_score',

    'format_consistency_score',

    'ransomware_score',

    'file_size',
]

# ============================================================
# DEMO
# ============================================================

if __name__ == "__main__":

    import sys

    if len(sys.argv) > 1:

        path = sys.argv[1]

        features = extract_all_features(path)

        print(f"\n=== FEATURES: {path} ===\n")

        for k, v in features.items():

            if isinstance(v, float):

                print(f"{k:<35}: {v:.6f}")

            else:

                print(f"{k:<35}: {v}")

    else:

        sample = os.urandom(50000)

        features = extract_all_features(sample)

        print("\n=== RANDOM DATA TEST ===\n")

        for k, v in features.items():

            if isinstance(v, float):

                print(f"{k:<35}: {v:.6f}")

            else:

                print(f"{k:<35}: {v}")