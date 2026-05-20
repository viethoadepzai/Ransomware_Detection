"""
generate_challenge_dataset.py

Ransomware Encryption Dataset Generator (Research Grade V2)
===========================================================

Hybrid & Multi-Algorithm Encryption Simulation
-----------------------------------------------
Modern ransomware NEVER uses a single cipher alone.
This generator simulates real-world hybrid patterns:

  - LockBit 3.0 : ChaCha20 body + AES-CBC header + intermittent skip
  - Ryuk/Conti   : AES-CBC partial + RSA key blob + ransom note append
  - BlackCat     : ChaCha20 full + AES footer seal
  - Play         : AES-CTR intermittent + RC4 header
  - Hive         : Multi-pass XOR + AES-CBC final
  - Royal        : Partial ChaCha20 + 3DES tail
  - WannaCry     : AES-CBC full + embedded key blob
  - Phobos       : AES-ECB pattern leakage + header destroy

Dataset Categories
------------------
1. hybrid_full/          - Full file, multi-algo
2. hybrid_partial/       - Partial encrypt, multi-algo
3. hybrid_intermittent/  - Skip-pattern, multi-algo
4. hybrid_header/        - Header-targeted, multi-algo
5. hybrid_layered/       - Multi-pass encryption
6. realistic_families/   - Real ransomware family patterns

Author: Research Edition V2
"""

import os
import json
import random
import struct
import hashlib

from Crypto.Cipher import (
    AES,
    DES3,
    ARC4,
    ChaCha20
)
from Crypto.Util.Padding import pad
from src.utils import ensure_dir

# =========================================================
# CONFIG
# =========================================================

OUTPUT_DIR = "data/ransomware_dataset"
random.seed(42)

# =========================================================
# REALISTIC FILE HEADERS (Magic Bytes)
# =========================================================

FILE_HEADERS = {
    'docx': b'PK\x03\x04\x14\x00\x06\x00\x08\x00',
    'xlsx': b'PK\x03\x04\x14\x00\x06\x00\x08\x00',
    'pptx': b'PK\x03\x04\x14\x00\x06\x00\x08\x00',
    'pdf':  b'%PDF-1.7\n',
    'jpg':  b'\xff\xd8\xff\xe0\x00\x10JFIF',
    'png':  b'\x89PNG\r\n\x1a\n',
    'zip':  b'PK\x03\x04',
    'doc':  b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1',
    'sql':  b'-- MySQL dump\n',
    'vmdk': b'KDMV',
    'bak':  b'TAPE\x00\x00\x00\x00',
    'mdf':  b'\x01\x0f\x00\x00',
}

RANSOM_NOTES = [
    b"\n\n--- YOUR FILES HAVE BEEN ENCRYPTED ---\n"
    b"Contact: dark_support@onion.tor\n"
    b"ID: %s\nBTC: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh\n",

    b"\n\n=== LOCKBIT 3.0 ===\n"
    b"All your important files are encrypted!\n"
    b"Victim ID: %s\n"
    b"Do NOT rename files. Do NOT use third party tools.\n",

    b"\n\n[RYUK]\nYour network has been penetrated.\n"
    b"Contact: ryuk_support@proton.me\n"
    b"Wallet: %s\n",
]

# =========================================================
# UTILS
# =========================================================

def save_file(path, data):
    with open(path, 'wb') as f:
        f.write(data)

def make_victim_id():
    return hashlib.md5(os.urandom(16)).hexdigest()[:16].upper()

def random_document(size=100_000, fmt='docx'):
    """Generate fake file with realistic header."""
    header = FILE_HEADERS.get(fmt, b'')
    body_size = size - len(header)
    # Mix structured text + binary to simulate real files
    text_block = (
        b"CONFIDENTIAL DOCUMENT\n"
        b"Financial report Q4-2025\n"
        b"Internal company data - DO NOT DISTRIBUTE\n"
        b"Revenue: $12,450,000 | Expenses: $8,200,000\n"
        b"Employee records attached below.\n"
    )
    body = b''
    while len(body) < body_size:
        if random.random() < 0.3:
            body += os.urandom(min(512, body_size - len(body)))
        else:
            body += text_block
    return header + body[:body_size]

def random_database(size=120_000):
    header = FILE_HEADERS['sql']
    rows = b''
    i = 0
    while len(rows) < size - len(header):
        rows += f"INSERT INTO users VALUES ({i},'user_{i}','pass_{i}','{make_victim_id()}');\n".encode()
        i += 1
    return header + rows[:size - len(header)]

def random_image(size=80_000, fmt='jpg'):
    header = FILE_HEADERS.get(fmt, b'\xff\xd8\xff\xe0')
    return header + os.urandom(size - len(header))

# =========================================================
# SINGLE CIPHER HELPERS
# =========================================================

def encrypt_aes_cbc(data):
    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data, AES.block_size))

def encrypt_aes_ctr(data):
    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CTR)
    return cipher.nonce + cipher.encrypt(data)

def encrypt_aes_ecb(data):
    key = os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))

def encrypt_chacha20(data):
    key = os.urandom(32)
    cipher = ChaCha20.new(key=key)
    return cipher.nonce + cipher.encrypt(data)

def encrypt_rc4(data):
    key = os.urandom(16)
    return ARC4.new(key).encrypt(data)

def encrypt_3des_cbc(data):
    key = DES3.adjust_key_parity(os.urandom(24))
    cipher = DES3.new(key, DES3.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data, 8))

def encrypt_3des_ecb(data):
    key = DES3.adjust_key_parity(os.urandom(24))
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(pad(data, 8))

def xor_encrypt(data, key=None):
    if key is None:
        key = os.urandom(32)
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % len(key)]
    return bytes(out)

def fake_rsa_blob():
    """Simulate an RSA-encrypted session key blob (256 bytes)."""
    return b'\x00\x02' + os.urandom(253) + b'\x00'

# =========================================================
# HYBRID ENCRYPTION TECHNIQUES
# =========================================================

def hybrid_chacha20_aes(data):
    """LockBit 3.0 style: ChaCha20 for body speed, AES-CBC for header precision."""
    header_size = min(4096, len(data))
    header_enc = encrypt_aes_cbc(data[:header_size])
    body_enc = encrypt_chacha20(data[header_size:])
    return header_enc + body_enc

def hybrid_aes_rc4(data):
    """Conti style: AES-CBC for first chunk, RC4 for remaining (speed)."""
    split = min(len(data) // 3, 32768)
    part1 = encrypt_aes_cbc(data[:split])
    part2 = encrypt_rc4(data[split:])
    return part1 + part2

def hybrid_chacha20_3des(data):
    """Royal style: ChaCha20 main body + 3DES-CBC tail seal."""
    tail_size = min(8192, len(data) // 4)
    body = encrypt_chacha20(data[:-tail_size])
    tail = encrypt_3des_cbc(data[-tail_size:])
    return body + tail

def hybrid_aes_ctr_rc4_header(data):
    """Play style: RC4 header destroy + AES-CTR body."""
    header_size = min(1024, len(data))
    header = encrypt_rc4(data[:header_size])
    body = encrypt_aes_ctr(data[header_size:])
    return header + body

def hybrid_multipass_xor_aes(data):
    """Hive style: XOR pre-pass then AES-CBC final."""
    xor_key = os.urandom(64)
    pass1 = xor_encrypt(data, xor_key)
    return encrypt_aes_cbc(pass1)

def hybrid_aes_chacha_interleaved(data, block=4096):
    """BlackCat style: alternate AES-CBC and ChaCha20 per block."""
    result = b''
    for i in range(0, len(data), block):
        chunk = data[i:i+block]
        if (i // block) % 2 == 0:
            result += encrypt_aes_cbc(chunk)
        else:
            result += encrypt_chacha20(chunk)
    return result

# =========================================================
# HYBRID PARTIAL TECHNIQUES
# =========================================================

def hybrid_partial_chacha_aes(data, pct=0.30):
    """Encrypt first pct% with ChaCha20, header with AES, rest plain."""
    enc_size = int(len(data) * pct)
    header_enc = encrypt_aes_cbc(data[:512])
    body_enc = encrypt_chacha20(data[512:enc_size])
    plain = data[enc_size:]
    return header_enc + body_enc + plain

def hybrid_partial_sandwich(data):
    """Encrypt header + footer, leave middle plain."""
    h = min(8192, len(data) // 4)
    t = min(4096, len(data) // 6)
    header = encrypt_aes_cbc(data[:h])
    footer = encrypt_chacha20(data[-t:])
    middle = data[h:-t] if t > 0 else data[h:]
    return header + middle + footer

def hybrid_partial_scattered(data, block=4096):
    """Encrypt random 40% of blocks with mixed algorithms."""
    result = b''
    ciphers = [encrypt_aes_cbc, encrypt_chacha20, encrypt_rc4]
    for i in range(0, len(data), block):
        chunk = data[i:i+block]
        if random.random() < 0.40:
            fn = random.choice(ciphers)
            result += fn(chunk)
        else:
            result += chunk
    return result

# =========================================================
# HYBRID INTERMITTENT TECHNIQUES
# =========================================================

def hybrid_intermittent_dual(data, step=3, block=4096):
    """Alternate between AES and ChaCha20 for encrypted blocks."""
    result = b''
    for i in range(0, len(data), block):
        chunk = data[i:i+block]
        idx = i // block
        if idx % step == 0:
            if idx % 2 == 0:
                result += encrypt_aes_cbc(chunk)
            else:
                result += encrypt_chacha20(chunk)
        else:
            result += chunk
    return result

def hybrid_intermittent_escalating(data, block=4096):
    """Start sparse, encrypt more densely toward end (time-pressure pattern)."""
    total = len(data) // block
    result = b''
    for i in range(0, len(data), block):
        chunk = data[i:i+block]
        idx = i // block
        ratio = idx / max(total, 1)
        if random.random() < (0.1 + 0.7 * ratio):
            result += encrypt_aes_cbc(chunk)
        else:
            result += chunk
    return result

# =========================================================
# HEADER CORRUPTION HYBRID
# =========================================================

def hybrid_header_multipass(data):
    """Destroy header with XOR + AES double-pass."""
    h = min(2048, len(data))
    header = xor_encrypt(data[:h])
    header = encrypt_aes_cbc(header)
    return header + data[h:]

def hybrid_header_replace_encrypt(data):
    """Replace header with RSA blob + encrypt next section."""
    blob = fake_rsa_blob()
    enc_section = encrypt_chacha20(data[256:8192])
    return blob + enc_section + data[8192:]

# =========================================================
# GENERATORS
# =========================================================

def _gen_category(cat_name, items):
    """Helper: save files and build metadata for a category."""
    out_dir = os.path.join(OUTPUT_DIR, cat_name)
    ensure_dir(out_dir)
    metadata = []
    for item in items:
        save_file(os.path.join(out_dir, item['file']), item['data'])
        metadata.append({
            "file": item['file'],
            "label": item['label'],
            "behavior": item['behavior'],
            "category": cat_name,
            "size": len(item['data']),
            "algorithms": item.get('algorithms', []),
        })
        print(f"  [+] {cat_name}/{item['file']} ({len(item['data']):,} bytes)")
    return metadata


def generate_hybrid_full():
    items = []
    sizes = [50_000, 100_000, 200_000, 500_000, 1_000_000]
    fmts = ['docx', 'pdf', 'xlsx', 'jpg', 'sql']
    configs = [
        ("ChaCha20+AES_CBC",  hybrid_chacha20_aes,         "finance_{}.docx.lockbit"),
        ("AES_CBC+RC4",       hybrid_aes_rc4,              "backup_{}.zip.conti"),
        ("ChaCha20+3DES",     hybrid_chacha20_3des,        "server_{}.vmdk.royal"),
        ("AES_CTR+RC4",       hybrid_aes_ctr_rc4_header,   "project_{}.docx.play"),
        ("XOR+AES_CBC",       hybrid_multipass_xor_aes,    "archive_{}.bak.hive"),
        ("AES_CBC+ChaCha20",  hybrid_aes_chacha_interleaved, "database_{}.mdf.blackcat"),
    ]
    for ci, (algos, fn, name_tpl) in enumerate(configs):
        for si, sz in enumerate(sizes[:3]):
            fmt = fmts[ci % len(fmts)]
            data = random_document(sz, fmt)
            enc = fn(data)
            note = random.choice(RANSOM_NOTES) % make_victim_id().encode()
            enc += note
            items.append({
                'file': name_tpl.format(f"{ci}_{si}"),
                'data': enc,
                'label': algos,
                'behavior': 'Uniform Encryption',
                'algorithms': algos.split('+'),
            })
    return _gen_category('hybrid_full', items)


def generate_hybrid_partial():
    items = []
    sizes = [80_000, 150_000, 300_000, 600_000]
    configs = [
        ("ChaCha20+AES_CBC",  hybrid_partial_chacha_aes,  "invoice_{}.xlsx.encrypted"),
        ("AES_CBC+ChaCha20",  hybrid_partial_sandwich,    "contract_{}.pdf.locked"),
        ("Mixed_Scattered",   hybrid_partial_scattered,   "photos_{}.zip.enc"),
    ]
    for ci, (algos, fn, name_tpl) in enumerate(configs):
        for si, sz in enumerate(sizes):
            data = random_document(sz, 'pdf' if ci == 1 else 'docx')
            enc = fn(data)
            items.append({
                'file': name_tpl.format(f"{ci}_{si}"),
                'data': enc,
                'label': algos,
                'behavior': 'Partial Encryption',
                'algorithms': algos.split('+') if '+' in algos else [algos],
            })
    return _gen_category('hybrid_partial', items)


def generate_hybrid_intermittent():
    items = []
    sizes = [100_000, 250_000, 500_000]
    configs = [
        ("AES+ChaCha20_Dual",  hybrid_intermittent_dual,       "report_{}.docx.lockbit"),
        ("AES_Escalating",     hybrid_intermittent_escalating,  "vm_{}.vmdk.blackcat"),
    ]
    for ci, (algos, fn, name_tpl) in enumerate(configs):
        for si, sz in enumerate(sizes):
            data = random_document(sz, 'docx')
            enc = fn(data)
            items.append({
                'file': name_tpl.format(f"{ci}_{si}"),
                'data': enc,
                'label': algos,
                'behavior': 'Intermittent Encryption',
                'algorithms': algos.split('+') if '+' in algos else [algos],
            })
    return _gen_category('hybrid_intermittent', items)


def generate_hybrid_header():
    items = []
    sizes = [60_000, 120_000, 300_000]
    configs = [
        ("XOR+AES_Multipass", hybrid_header_multipass,       "photo_{}.png.encrypted"),
        ("RSA_Blob+ChaCha20", hybrid_header_replace_encrypt, "scan_{}.pdf.lockbit"),
    ]
    for ci, (algos, fn, name_tpl) in enumerate(configs):
        for si, sz in enumerate(sizes):
            fmt = 'png' if ci == 0 else 'pdf'
            data = random_image(sz, fmt) if fmt == 'png' else random_document(sz, fmt)
            enc = fn(data)
            items.append({
                'file': name_tpl.format(f"{ci}_{si}"),
                'data': enc,
                'label': algos,
                'behavior': 'Header Tampering',
                'algorithms': algos.split('+'),
            })
    return _gen_category('hybrid_header', items)


def generate_hybrid_layered():
    """Multi-pass: data encrypted multiple times with different algorithms."""
    items = []
    sizes = [50_000, 100_000, 200_000]

    for si, sz in enumerate(sizes):
        data = random_document(sz, 'docx')
        # Pass 1: XOR
        p1 = xor_encrypt(data)
        # Pass 2: RC4
        p2 = encrypt_rc4(p1)
        # Pass 3: AES-CBC
        p3 = encrypt_aes_cbc(p2)
        items.append({
            'file': f"layered_triple_{si}.docx.crypt",
            'data': p3,
            'label': 'XOR+RC4+AES_CBC',
            'behavior': 'Uniform Encryption',
            'algorithms': ['XOR', 'RC4', 'AES_CBC'],
        })

    for si, sz in enumerate(sizes):
        data = random_database(sz)
        # Pass 1: AES-ECB (leaks patterns)
        p1 = encrypt_aes_ecb(data)
        # Pass 2: ChaCha20 (masks patterns)
        p2 = encrypt_chacha20(p1)
        items.append({
            'file': f"layered_double_{si}.sql.ryk",
            'data': p2,
            'label': 'AES_ECB+ChaCha20',
            'behavior': 'Uniform Encryption',
            'algorithms': ['AES_ECB', 'ChaCha20'],
        })

    return _gen_category('hybrid_layered', items)


def generate_realistic_families():
    """Mimic specific ransomware family behaviors exactly."""
    items = []

    # --- LockBit 3.0 ---
    for i, sz in enumerate([200_000, 500_000, 1_000_000]):
        data = random_document(sz, 'docx')
        enc = hybrid_intermittent_dual(data, step=4, block=4096)
        note = RANSOM_NOTES[1] % make_victim_id().encode()
        items.append({
            'file': f"lockbit3_{i}.docx.lockbit",
            'data': enc + note,
            'label': 'LockBit3.0',
            'behavior': 'Intermittent Encryption',
            'algorithms': ['AES_CBC', 'ChaCha20'],
        })

    # --- Ryuk ---
    for i, sz in enumerate([150_000, 300_000]):
        data = random_database(sz)
        blob = fake_rsa_blob()
        enc = hybrid_partial_chacha_aes(data, pct=0.25)
        note = RANSOM_NOTES[2] % make_victim_id().encode()
        items.append({
            'file': f"ryuk_{i}.sql.ryk",
            'data': blob + enc + note,
            'label': 'Ryuk',
            'behavior': 'Partial Encryption',
            'algorithms': ['RSA_blob', 'ChaCha20', 'AES_CBC'],
        })

    # --- Conti ---
    for i, sz in enumerate([100_000, 400_000]):
        data = random_document(sz, 'xlsx')
        enc = hybrid_aes_rc4(data)
        items.append({
            'file': f"conti_{i}.xlsx.conti",
            'data': enc,
            'label': 'Conti',
            'behavior': 'Uniform Encryption',
            'algorithms': ['AES_CBC', 'RC4'],
        })

    # --- BlackCat/ALPHV ---
    for i, sz in enumerate([200_000, 800_000]):
        data = random_document(sz, 'pdf')
        enc = hybrid_aes_chacha_interleaved(data, block=8192)
        items.append({
            'file': f"blackcat_{i}.pdf.blackcat",
            'data': enc,
            'label': 'BlackCat',
            'behavior': 'Intermittent Encryption',
            'algorithms': ['AES_CBC', 'ChaCha20'],
        })

    # --- Play ---
    for i in range(2):
        data = random_document(250_000, 'docx')
        enc = hybrid_aes_ctr_rc4_header(data)
        items.append({
            'file': f"play_{i}.docx.play",
            'data': enc,
            'label': 'Play',
            'behavior': 'Partial Encryption',
            'algorithms': ['RC4', 'AES_CTR'],
        })

    # --- Hive ---
    for i in range(2):
        data = random_document(300_000, 'pdf')
        enc = hybrid_multipass_xor_aes(data)
        items.append({
            'file': f"hive_{i}.pdf.hive",
            'data': enc,
            'label': 'Hive',
            'behavior': 'Uniform Encryption',
            'algorithms': ['XOR', 'AES_CBC'],
        })

    # --- Royal ---
    for i in range(2):
        data = random_document(350_000, 'xlsx')
        enc = hybrid_chacha20_3des(data)
        items.append({
            'file': f"royal_{i}.xlsx.royal",
            'data': enc,
            'label': 'Royal',
            'behavior': 'Uniform Encryption',
            'algorithms': ['ChaCha20', '3DES_CBC'],
        })

    # --- WannaCry style (AES full + key blob) ---
    for i in range(2):
        data = random_image(100_000, 'jpg')
        blob = fake_rsa_blob()
        enc = encrypt_aes_cbc(data)
        items.append({
            'file': f"wannacry_{i}.jpg.wcry",
            'data': blob + enc,
            'label': 'WannaCry',
            'behavior': 'Uniform Encryption',
            'algorithms': ['RSA_blob', 'AES_CBC'],
        })

    # --- Phobos (ECB leakage + header destroy) ---
    for i in range(2):
        data = random_document(100_000, 'doc')
        header_enc = encrypt_rc4(data[:1024])
        body_ecb = encrypt_aes_ecb(data[1024:])
        items.append({
            'file': f"phobos_{i}.doc.phobos",
            'data': header_enc + body_ecb,
            'label': 'Phobos',
            'behavior': 'Pattern Leakage',
            'algorithms': ['RC4', 'AES_ECB'],
        })

    return _gen_category('realistic_families', items)


# =========================================================
# MAIN
# =========================================================

def generate_ransomware_dataset():
    ensure_dir(OUTPUT_DIR)

    print("=" * 60)
    print("RANSOMWARE DATASET GENERATOR V2 (Hybrid Edition)")
    print("=" * 60)

    all_metadata = []

    generators = [
        ("Hybrid Full Encryption",    generate_hybrid_full),
        ("Hybrid Partial Encryption",  generate_hybrid_partial),
        ("Hybrid Intermittent",        generate_hybrid_intermittent),
        ("Hybrid Header Corruption",   generate_hybrid_header),
        ("Hybrid Multi-Layer",         generate_hybrid_layered),
        ("Realistic Families",         generate_realistic_families),
    ]

    for name, gen_fn in generators:
        print(f"\n--- {name} ---")
        result = gen_fn()
        all_metadata.extend(result)

    # Save metadata
    meta_path = os.path.join(OUTPUT_DIR, 'metadata.json')
    with open(meta_path, 'w', encoding='utf-8') as f:
        json.dump(all_metadata, f, indent=2, ensure_ascii=False)

    # Summary
    print("\n" + "=" * 60)
    print(f"Total files generated: {len(all_metadata)}")

    print("\nBy Behavior:")
    beh = {}
    for m in all_metadata:
        b = m['behavior']
        beh[b] = beh.get(b, 0) + 1
    for k, v in sorted(beh.items()):
        print(f"  {k}: {v}")

    print("\nBy Algorithm Combo:")
    algo = {}
    for m in all_metadata:
        a = m['label']
        algo[a] = algo.get(a, 0) + 1
    for k, v in sorted(algo.items()):
        print(f"  {k}: {v}")

    print(f"\nMetadata saved: {meta_path}")
    print("=" * 60)


# =========================================================
# ENTRYPOINT
# =========================================================

if __name__ == "__main__":
    generate_ransomware_dataset()