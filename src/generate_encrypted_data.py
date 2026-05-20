"""
Behavioral Ransomware Dataset Generator (V9)
============================================

Sinh dataset theo HÀNH VI ransomware
thay vì phân loại cipher.

Classes:
--------
1. NoEncryption
2. Uniform_Encrypted
3. Intermittent_Encrypted
4. Partial_Encrypted
5. Obfuscation_Base64
6. Pattern_Leakage

Research-grade behavioral dataset.
"""

import os
import base64
import random
import hashlib

from collections import Counter

from src.utils import (
    setup_logger,
    ensure_dir
)

logger = setup_logger(
    'behavioral_dataset',
    'logs/generate_behavioral_dataset.log'
)

# ============================================================
# CRYPTO
# ============================================================

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ============================================================
# CONFIG
# ============================================================

BLOCK_SIZE = 4096

# ============================================================
# AES CBC
# ============================================================

def aes_encrypt(data):

    key = hashlib.sha256(
        os.urandom(32)
    ).digest()

    cipher = AES.new(
        key,
        AES.MODE_CBC
    )

    padded = pad(data, AES.block_size)

    ciphertext = (
        cipher.iv +
        cipher.encrypt(padded)
    )

    return ciphertext

# ============================================================
# FULL ENCRYPTION
# ============================================================

def uniform_encrypt(data):

    return aes_encrypt(data)

# ============================================================
# INTERMITTENT ENCRYPTION
# ============================================================

def intermittent_encrypt(data):

    chunks = []

    encrypt_next = False

    for i in range(0, len(data), BLOCK_SIZE):

        chunk = data[i:i + BLOCK_SIZE]

        if encrypt_next:

            chunk = aes_encrypt(chunk)

        chunks.append(chunk)

        encrypt_next = not encrypt_next

    return b''.join(chunks)

# ============================================================
# PARTIAL ENCRYPTION
# ============================================================

def partial_encrypt(data):

    if len(data) < BLOCK_SIZE * 4:

        return aes_encrypt(data)

    split = len(data) // 3

    encrypted_part = aes_encrypt(
        data[:split]
    )

    return encrypted_part + data[split:]

# ============================================================
# ECB PATTERN LEAKAGE
# ============================================================

def pattern_leakage_encrypt(data):

    key = hashlib.sha256(
        os.urandom(32)
    ).digest()

    cipher = AES.new(
        key,
        AES.MODE_ECB
    )

    padded = pad(data, AES.block_size)

    return cipher.encrypt(padded)

# ============================================================
# BASE64 OBFUSCATION
# ============================================================

def obfuscate_base64(data):

    encoded = base64.b64encode(data)

    return encoded

# ============================================================
# LOAD REAL FILES
# ============================================================

def load_real_files(real_dir):

    files = []

    for root, _, filenames in os.walk(real_dir):

        for f in filenames:

            path = os.path.join(root, f)

            files.append(path)

    return files

# ============================================================
# GENERATE DATASET
# ============================================================

def generate_encrypted_dataset(config):

    real_dir = config['data'].get(
        'real_sample_dir',
        'data/realsample'
    )

    output_dir = config['data'].get(
        'encrypted_samples_dir',
        'data/raw/encrypted_samples'
    )

    samples_per_class = config['data'].get(
        'samples_per_class',
        500
    )

    ensure_dir(output_dir)

    real_files = load_real_files(real_dir)

    if not real_files:

        raise RuntimeError(
            "No real files found."
        )

    logger.info(
        f"Found {len(real_files)} real files."
    )

    generators = {

        "Uniform_Encrypted":
            uniform_encrypt,

        "Intermittent_Encrypted":
            intermittent_encrypt,

        "Partial_Encrypted":
            partial_encrypt,

        "Obfuscation_Base64":
            obfuscate_base64,

        "Pattern_Leakage":
            pattern_leakage_encrypt,
    }

    metadata = []

    sample_id = 0

    # ========================================================
    # SAFE FILES
    # ========================================================

    safe_dir = os.path.join(
        output_dir,
        "NoEncryption"
    )

    ensure_dir(safe_dir)

    logger.info(
        "Generating safe samples..."
    )

    for i in range(samples_per_class):

        src = random.choice(real_files)

        try:

            with open(src, 'rb') as f:

                data = f.read()

            out_path = os.path.join(
                safe_dir,
                f"safe_{i}.bin"
            )

            with open(out_path, 'wb') as f:

                f.write(data)

            metadata.append({

                "sample_id": sample_id,

                "file_path": out_path,

                "algorithm": "NoEncryption",
            })

            sample_id += 1

        except Exception as e:

            logger.error(e)

    # ========================================================
    # BEHAVIORAL CLASSES
    # ========================================================

    for class_name, fn in generators.items():

        logger.info(
            f"Generating {class_name}"
        )

        class_dir = os.path.join(
            output_dir,
            class_name
        )

        ensure_dir(class_dir)

        for i in range(samples_per_class):

            src = random.choice(real_files)

            try:

                with open(src, 'rb') as f:

                    data = f.read()

                transformed = fn(data)

                out_path = os.path.join(
                    class_dir,
                    f"{class_name}_{i}.bin"
                )

                with open(out_path, 'wb') as f:

                    f.write(transformed)

                metadata.append({

                    "sample_id": sample_id,

                    "file_path": out_path,

                    "algorithm": class_name,
                })

                sample_id += 1

            except Exception as e:

                logger.error(
                    f"{class_name}: {e}"
                )

    # ========================================================
    # SUMMARY
    # ========================================================

    logger.info("=" * 60)

    logger.info(
        f"TOTAL SAMPLES: {len(metadata)}"
    )

    counts = Counter(
        m['algorithm']
        for m in metadata
    )

    for k, v in counts.items():

        logger.info(f"{k}: {v}")

    logger.info("=" * 60)

    return metadata

# ============================================================
# ENTRY
# ============================================================

if __name__ == "__main__":

    from src.utils import load_config

    config = load_config(
        'config/config.yaml'
    )

    generate_encrypted_dataset(config)