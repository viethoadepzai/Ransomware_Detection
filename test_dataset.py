"""Verify all generated ransomware samples are detected as encrypted."""
import os, sys, json
sys.path.insert(0, os.path.dirname(__file__))
from src.detect_encryption import load_models, detect_file

def main():
    model1, model2, le2, cols_s1, cols_s2 = load_models()
    
    meta_path = "data/ransomware_dataset/metadata.json"
    with open(meta_path, 'r') as f:
        metadata = json.load(f)
    
    passed = 0
    failed = 0
    fails = []
    
    for item in metadata:
        cat = item['category']
        fname = item['file']
        fpath = os.path.join("data/ransomware_dataset", cat, fname)
        
        if not os.path.exists(fpath):
            print(f"  [SKIP] {fpath}")
            continue
        
        result = detect_file(fpath, model1, model2, le2, cols_s1, cols_s2)
        is_enc = result.get('encrypted', False)
        risk = result.get('risk_level', 0)
        
        if is_enc:
            passed += 1
        else:
            failed += 1
            fails.append((fname, risk, item['label']))
            print(f"  [FAIL] {fname:50s} risk={risk:.4f}  algos={item['label']}")
    
    print(f"\nResults: {passed} passed, {failed} failed out of {passed+failed}")
    if fails:
        print("\nFailed files:")
        for f, r, a in fails:
            print(f"  {f:50s} risk={r:.4f} ({a})")
    else:
        print("ALL RANSOMWARE SAMPLES CORRECTLY DETECTED!")

if __name__ == "__main__":
    main()
