import json, joblib, pandas as pd, sys, os
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, '.')
from src.features import extract_static_features

# Tim file Chrome hoac Office
CANDIDATE_PATHS = [
    r'C:/Program Files/Google/Chrome/Application/chrome.exe',
    r'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    r'C:/Users/Admin/Downloads/ChromeSetup.exe',
    r'C:/Users/Admin/Downloads/OfficeSetup.exe',
    r'C:/Users/Admin/Desktop/OfficeSetup.exe',
    r'C:/Windows/System32/notepad.exe',
    r'C:/Windows/System32/calc.exe',
    r'C:/Windows/System32/mspaint.exe',
]

files_to_test = {}
for p in CANDIDATE_PATHS:
    if os.path.exists(p):
        name = os.path.basename(p)
        files_to_test[name] = p
        if len(files_to_test) >= 4:
            break

# Add the Ryuk files for comparison
files_to_test['RYUK_8f36'] = r'test/8f368b029a3a5517cb133529274834585d087a2d3a5875d03ea38e5774019c8a/8f368b029a3a5517cb133529274834585d087a2d3a5875d03ea38e5774019c8a.exe'
files_to_test['RYUK_bf57'] = r'test/bf575ce1c9425bc44f5cabbc34366e0e92ef369db0a8b69942c5bdb1cca9b800/bf575ce1c9425bc44f5cabbc34366e0e92ef369db0a8b69942c5bdb1cca9b800.exe'

with open('models/features_list.json') as f:
    model_features = json.load(f)
model = joblib.load('models/ryuk_xgboost_model.joblib')

dyn_zeros = ['dyn_file_write_count','dyn_file_rename_count','dyn_suspicious_extension_count',
    'dyn_anti_recovery_cmds_count','dyn_registry_modified_count','dyn_rename_ratio',
    'dyn_suspicious_ext_ratio','dyn_crypto_api_ratio','dyn_file_api_ratio','dyn_dirs_ratio',
    'dyn_write_burst_score','dyn_unique_dirs_touched','dyn_file_type_diversity']

print(f"{'File':<20} {'Prob':>7} {'Entropy':>8} {'SecEnt':>8} {'TotImp':>8} {'FileAPI':>8} {'NetAPI':>8} {'RegAPI':>8} {'CryAPI':>8} {'Dlls':>6} {'Result'}")
print("-" * 120)

for label, path in files_to_test.items():
    if not os.path.exists(path):
        print(f"{label:<20}  FILE NOT FOUND")
        continue
    feat = extract_static_features(path)
    feat['dyn_has_dynamic'] = 0
    feat.update({k: 0.0 for k in dyn_zeros})
    df = pd.DataFrame([feat])
    for col in model_features:
        if col not in df.columns:
            df[col] = 0.0
    df = df[model_features]
    prob = model.predict_proba(df.values)[0][1]
    verdict = 'RYUK!' if prob > 0.5 else 'SAFE'
    print(f"{label:<20} {prob*100:>6.1f}% {feat['static_global_entropy']:>8.4f} {feat['static_max_section_entropy']:>8.4f} {feat['static_total_imports']:>8} {feat['static_file_api_count']:>8} {feat['static_network_api_count']:>8} {feat['static_registry_api_count']:>8} {feat['static_crypto_api_count']:>8} {feat['static_suspicious_dlls']:>6}  [{verdict}]")
