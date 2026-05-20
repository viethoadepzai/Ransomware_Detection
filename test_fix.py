"""Quick test to verify the 4 encrypted files are correctly detected."""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from src.detect_encryption import load_models, detect_file

def main():
    model1, model2, le2, cols_s1, cols_s2 = load_models()

    # The 4 encrypted files that were previously misclassified
    encrypted_files = [
        r"data\11\encrypted\backup.zip.ryk",
        r"data\11\encrypted\database.sql.encrypted",
        r"data\11\encrypted\document.docx.locked",
        r"data\11\encrypted\vmware.vmdk.lockbit",
    ]

    # A few safe files to make sure we don't false-positive
    safe_files = []
    realsample_dir = r"data\realsample"
    if os.path.exists(realsample_dir):
        for f in os.listdir(realsample_dir)[:3]:
            safe_files.append(os.path.join(realsample_dir, f))

    print("=" * 70)
    print("TESTING ENCRYPTED FILES (should ALL be detected as ENCRYPTED)")
    print("=" * 70)
    
    enc_results = []
    for fpath in encrypted_files:
        if not os.path.exists(fpath):
            print(f"  [SKIP] {fpath} not found")
            continue
        result = detect_file(fpath, model1, model2, le2, cols_s1, cols_s2)
        status = "ENCRYPTED" if result.get('encrypted') else "SAFE"
        risk = result.get('risk_level', 0)
        ok = "OK" if result.get('encrypted') else "FAIL"
        print(f"  [{ok}] {result['file']:45s} => {status}  (risk={risk:.4f})")
        enc_results.append(result.get('encrypted', False))

    print()
    print("=" * 70)
    print("TESTING SAFE FILES (should ALL be detected as SAFE)")
    print("=" * 70)
    
    safe_results = []
    for fpath in safe_files:
        result = detect_file(fpath, model1, model2, le2, cols_s1, cols_s2)
        status = "ENCRYPTED" if result.get('encrypted') else "SAFE"
        risk = result.get('risk_level', 0)
        ok = "OK" if not result.get('encrypted') else "FAIL"
        print(f"  [{ok}] {result['file']:45s} => {status}  (risk={risk:.4f})")
        safe_results.append(not result.get('encrypted', True))

    print()
    print("=" * 70)
    all_enc = all(enc_results) if enc_results else False
    all_safe = all(safe_results) if safe_results else True
    
    if all_enc and all_safe:
        print("RESULT: ALL TESTS PASSED (OK)")
    else:
        if not all_enc:
            print("RESULT: ENCRYPTED FILES STILL MISCLASSIFIED (FAIL)")
        if not all_safe:
            print("RESULT: SAFE FILES FALSE-POSITIVE (FAIL)")
    print("=" * 70)

if __name__ == "__main__":
    main()
