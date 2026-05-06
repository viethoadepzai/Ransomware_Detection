import sys
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, '.')
import pefile

for path, label in [
    (r'C:/Windows/System32/notepad.exe', 'notepad'),
    (r'C:/Program Files/Google/Chrome/Application/chrome.exe', 'chrome'),
]:
    try:
        pe = pefile.PE(path)
        all_imports = []
        dlls = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', 'ignore').lower() if entry.dll else ''
            dlls.append(dll)
            for imp in entry.imports:
                if imp.name:
                    all_imports.append(imp.name.decode('utf-8', 'ignore'))
                else:
                    all_imports.append(f'ordinal_{imp.ordinal}')
        named = [x for x in all_imports if not x.startswith('ordinal_')]
        print(f"\n=== {label} ===")
        print(f"  DLLs ({len(dlls)}): {dlls[:5]}...")
        print(f"  Total imports from pefile: {len(all_imports)}")
        print(f"  Named: {len(named)}, Ordinal-only: {len(all_imports)-len(named)}")
        print(f"  First named: {named[:10]}")
    except Exception as e:
        print(f"{label}: ERROR {e}")
