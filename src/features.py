import os
import json
import logging
import math
import time
from collections import Counter
from src.utils import setup_logger

logger = setup_logger('features', 'logs/features.log')

# === CÁC DANH SÁCH ĐẶC TRƯNG CỦA RANSOMWARE ===
CRYPTO_APIS = [
    'cryptencrypt', 'cryptdecrypt', 'cryptgenkey', 'cryptderivekey',
    'cryptacquirecontext', 'cryptacquirecontexta', 'cryptacquirecontextw',
    'crypthashdata', 'cryptgethashparam', 'cryptcreatehash', 'cryptdestroyhash',
    'bcryptencrypt', 'bcryptdecrypt', 'bcryptgeneratekeypair', 'bcryptopenalgorithmprovider',
]
FILE_APIS = [
    # CreateFile/OpenFile
    'createfile', 'createfilea', 'createfilew', 'openfile', 'createfiletransacted',
    # ReadFile/WriteFile
    'readfile', 'writefile', 'readfileex', 'writefileex',
    # MoveFile/CopyFile/DeleteFile
    'movefile', 'movefilea', 'movefilew', 'movefileex', 'movefileexa', 'movefileexw',
    'copyfile', 'copyfilea', 'copyfilew', 'copyfileex', 'copyfileexa', 'copyfileexw',
    'deletefile', 'deletefilea', 'deletefilew',
    # SetFileAttributes
    'setfileattributes', 'setfileattributesa', 'setfileattributesw',
    'getfileattributes', 'getfileattributesa', 'getfileattributesw',
    # FindFile / Directory
    'findfirstfile', 'findfirstfilea', 'findfirstfilew', 'findnextfile', 'findclose',
    'createdir', 'createdirectory', 'createdirectorya', 'createdirectoryw',
    'removedir', 'removedirectorya', 'removedirectoryw',
    # GetFileSize / SetFilePointer
    'getfilesize', 'getfilesizeex', 'setfilepointer', 'setfilepointerex',
    # CloseHandle / FlushFileBuffers
    'closehandle', 'flushfilebuffers',
    # === APIs của BENIGN software (notepad, office, chrome) ===
    # GDI (notepad dùng nhiều)
    'setmapmode', 'setviewportextex', 'setwindowextex', 'lptodp', 'setbkmode',
    'gettextmetrics', 'gettextmetricsw', 'textout', 'textouta', 'textoutw',
    'abortdoc', 'enddoc', 'setabortproc', 'startdoc', 'startdoca', 'startdocw',
    'startpage', 'endpage', 'getdevicecaps', 'createfont', 'createfontw',
    'createpen', 'createsolidbrush', 'selectobject', 'deleteobject', 'bitblt',
    'stretchblt', 'getdibits', 'setdibitstodevice',
    # Shell/Explorer
    'shgetfolderpath', 'shgetfolderpatha', 'shgetfolderpathw',
    'shbrowseforfolder', 'shfileop', 'shgetpathfromidlist',
    # Common file dialog
    'getopenfilename', 'getsavefilename', 'getopenfilea', 'getsavefilea',
    'getopenfilenamew', 'getsavefilenamew',
    # Memory-mapped file
    'createfilemapping', 'createfilemappinga', 'createfilemappingw',
    'mapviewoffile', 'unmapviewoffile',
    # GetTempPath/GetTempFile
    'gettemppath', 'gettempfilea', 'gettempfilew', 'gettemppatwa',
    # Version info
    'getfileversioninfo', 'getfileversioninfoa', 'getfileversioninfow',
    'getfileversioninfosize', 'getfileversioninfosizea', 'getfileversioninfosizew',
    'verqueryvalue', 'verqueryvaluea', 'verqueryvaluew',
]
NETWORK_APIS = [
    # WinInet
    'internetopen', 'internetopena', 'internetopenw',
    'internetconnect', 'internetconnecta', 'internetconnectw',
    'httpopenrequest', 'httpopenrequesta', 'httpopenrequestw',
    'httpsendrequest', 'httpsendrequesta', 'httpsendreequestw',
    'internetreadfile', 'internetwritefile', 'internetclosehandle',
    'internetqueryoption', 'internetsetoption',
    # Winsock
    'wsastartup', 'connect', 'send', 'recv', 'closesocket',
    'gethostbyname', 'gethostbyaddr', 'getaddrinfo', 'freeaddrinfo',
    'socket', 'bind', 'listen', 'accept', 'select', 'shutdown',
    # WinHTTP
    'winhttpopen', 'winhttpopenw', 'winhttpconnect', 'winhttpsendrequest',
    'winhttpreceiveresponse', 'winhttpreaddata', 'winhttpclosehandle',
    # DNS
    'dnsquery', 'dnsqueryex', 'dnsrecordlistfree',
    # Chrome / modern apps
    'acquiresrwlockexclusive', 'acquiresrwlockshared', 'releasesrwlockexclusive',
]
REGISTRY_APIS = [
    'regsetvalue', 'regsetvaluea', 'regsetvaluew', 'regsetvalueex', 'regsetvalueexa', 'regsetvalueexw',
    'regcreatekey', 'regcreatekeya', 'regcreatekeyw', 'regcreatekeyex', 'regcreatekeyexa', 'regcreatekeyexw',
    'regopenkey', 'regopenkeya', 'regopenkeyw', 'regopenkeyex', 'regopenkeyexa', 'regopenkeyexw',
    'regclosekey', 'regqueryvalue', 'regqueryvaluea', 'regqueryvaluew',
    'regqueryvalueex', 'regqueryvalueexa', 'regqueryvalueexw',
    'regdeletekey', 'regdeletekeya', 'regdeletekeyw', 'regdeletevalue',
    'regenumkey', 'regenumkeya', 'regenumkeyw', 'regenumkeyex',
    'regenumvalue', 'regenumvaluea', 'regenumvaluew',
    # Privilege / token
    'lookupprivilegevalue', 'lookupprivilegevaluea', 'lookupprivilegevaluew',
    'adjusttokenprivileges', 'openprocesstoken', 'openthreadtoken',
]
SUSPICIOUS_DLLS = ['advapi32.dll', 'crypt32.dll']
SUSPICIOUS_EXTENSIONS = ['.ryk', '.encrypted', '.crypt', '.locky', '.locked']
ANTI_RECOVERY_CMDS = ['vssadmin', 'delete shadows', 'bcdedit', 'recoveryenabled no', 'wbadmin']

def calculate_entropy(data):
    """
    Tính toán mức độ hỗn loạn (Entropy) của một mảng bytes.
    Tối ưu hóa: Sử dụng collections.Counter để đạt O(N), nhanh hơn hàng nghìn lần so với O(N^2).
    """
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log(p_x, 2)
    return entropy

def extract_static_features(file_path):
    """Trích xuất đặc trưng tĩnh."""
    features = {
        "static_global_entropy": 0.0,
        "static_max_section_entropy": 0.0,
        "static_has_overlay": 0,
        "static_suspicious_timestamp": 0,
        "static_rwx_sections": 0,
        "static_empty_iat": 0,
        "static_total_imports": 0,
        "static_dll_count": 0,
        "static_api_ratio": 0.0,
        "static_crypto_api_count": 0,
        "static_file_api_count": 0,
        "static_network_api_count": 0,
        "static_registry_api_count": 0,
        "static_suspicious_dlls": 0,
        "static_number_of_sections": 0
    }
    
    try:
        import pefile
    except ImportError:
        logger.warning("Thư viện 'pefile' chưa cài đặt. Bỏ qua phân tích tĩnh.")
        return features

    if not os.path.exists(file_path):
        return features

    logger.info(f"Bắt đầu phân tích tĩnh (Static Analysis) cho: {file_path}")
    try:
        with open(file_path, 'rb') as f:
            features["static_global_entropy"] = calculate_entropy(f.read())
        
        pe = pefile.PE(file_path)
        features['static_number_of_sections'] = pe.FILE_HEADER.NumberOfSections
        
        # Kiểm tra Timestamp giả mạo
        timestamp = pe.FILE_HEADER.TimeDateStamp
        current_time = int(time.time())
        if timestamp == 0 or timestamp > current_time:
            features["static_suspicious_timestamp"] = 1
        
        # Tính Entropy từng Section và đếm số lượng RWX section (Self-modifying code)
        max_sec_ent = 0.0
        rwx_count = 0
        for section in pe.sections:
            sec_ent = calculate_entropy(section.get_data())
            if sec_ent > max_sec_ent:
                max_sec_ent = sec_ent
            flags = section.Characteristics
            if (flags & 0x20000000) and (flags & 0x80000000): # Execute + Write
                rwx_count += 1
        features["static_max_section_entropy"] = max_sec_ent
        features["static_rwx_sections"] = rwx_count
        
        # Dò tìm Overlay (dữ liệu rác/chữ ký giả được nhồi vào cuối file)
        overlay = pe.get_overlay()
        if overlay and len(overlay) > 0:
            features["static_has_overlay"] = 1
        else:
            features["static_has_overlay"] = 0
        
        crypto_count = 0
        file_api_count = 0
        network_count = 0
        registry_count = 0
        suspicious_dll_count = 0
        total_imports = 0
        dll_count = 0  # số lượng DLL import
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            all_imports = []
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_count += 1
                if entry.dll:
                    dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
                    if dll_name in SUSPICIOUS_DLLS:
                        suspicious_dll_count += 1
                    
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore').lower()
                        all_imports.append(func_name)
                        if func_name in CRYPTO_APIS:
                            crypto_count += 1
                        if func_name in FILE_APIS:
                            file_api_count += 1
                        if func_name in NETWORK_APIS:
                            network_count += 1
                        if func_name in REGISTRY_APIS:
                            registry_count += 1

            total_imports = len(all_imports)

            # Kiểm tra Empty/Sparse IAT — dấu hiệu file bị PACKED
            # Case 1: import ít + có LoadLibrary/GetProcAddress (loader stub cổ điển)
            has_loadlib    = any('loadlibrary' in f for f in all_imports)
            has_getproc    = any('getprocaddress' in f for f in all_imports)
            # Case 2: import cực ít (<=10) → IAT gần rỗng → rất khả năng packed
            very_sparse_iat = total_imports <= 10
            if (very_sparse_iat and has_loadlib and has_getproc) or (very_sparse_iat and total_imports <= 5):
                features["static_empty_iat"] = 1
        
        features["static_total_imports"]    = total_imports
        features["static_dll_count"]         = dll_count
        named_api_count = crypto_count + file_api_count + network_count + registry_count
        # api_ratio: tỷ lệ named API / tổng imports — thấp ở packed malware, cao ở benign
        features["static_api_ratio"]         = named_api_count / max(total_imports, 1)
        features["static_crypto_api_count"]  = crypto_count
        features["static_file_api_count"]    = file_api_count
        features["static_network_api_count"] = network_count
        features["static_registry_api_count"]= registry_count
        features["static_suspicious_dlls"]   = suspicious_dll_count
    except Exception as e:
        logger.error(f"Lỗi khi phân tích PE: {e}")

    return features

def extract_dynamic_features(log_path):
    """
    Trích xuất đặc trưng động (Behavioral Analysis) cho Ransomware/Ryuk.

    Hỗ trợ đa format JSON:
      - CAPE Sandbox / CAPEv2 chuẩn: behavior.summary.file_written / file_moved
      - Custom sandbox format: file_system.files_created, encryption_activity.api_calls
      - Fallback hoàn toàn: suy ra counts từ API calls trong processes[].calls[]

    Priority chain cho file counts:
      1. behavior.summary  (CAPE chuẩn)
      2. file_system       (custom format)
      3. API-derived       (WriteFile / MoveFile calls)
    """
    features = {
        # Raw counts
        "dyn_file_write_count": 0,
        "dyn_file_rename_count": 0,
        "dyn_suspicious_extension_count": 0,
        "dyn_anti_recovery_cmds_count": 0,
        "dyn_registry_modified_count": 0,

        # Ratio features
        "dyn_rename_ratio": 0.0,
        "dyn_suspicious_ext_ratio": 0.0,
        "dyn_crypto_api_ratio": 0.0,
        "dyn_file_api_ratio": 0.0,
        "dyn_dirs_ratio": 0.0,
        "dyn_has_dynamic": 0,

        # Burst & Spread features
        "dyn_write_burst_score": 0.0,
        "dyn_unique_dirs_touched": 0,
        "dyn_file_type_diversity": 0
    }

    if not os.path.exists(log_path):
        return features

    logger.info(f"Bắt đầu phân tích hành vi động cho log: {log_path}")
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        features["dyn_has_dynamic"] = 1
        duration = data.get('info', {}).get('duration', 1) or 1
        behavior = data.get('behavior', {})
        summary  = behavior.get('summary', {})
        processes = behavior.get('processes', [])

        # ── BƯỚC 1: Dynamic API Behavior (từ processes[].calls[]) ─────────────
        dyn_crypto_count   = 0
        dyn_file_api_count = 0
        total_api_calls    = 0
        api_derived_write  = 0   # fallback khi summary rỗng
        api_derived_rename = 0

        for proc in processes:
            calls = proc.get('calls', [])
            total_api_calls += len(calls)
            for call in calls:
                api_name = call.get('api', '').lower()
                if any(c in api_name for c in CRYPTO_APIS):
                    dyn_crypto_count += 1
                if any(f in api_name for f in FILE_APIS):
                    dyn_file_api_count += 1
                if 'writefile' in api_name or 'createfile' in api_name:
                    api_derived_write += 1
                if 'movefile' in api_name:
                    api_derived_rename += 1

            # Anti-recovery: kiểm tra cả command_line lẫn commands_executed
            cmdline = proc.get('command_line', '').lower()
            for cmd in ANTI_RECOVERY_CMDS:
                if cmd in cmdline:
                    features['dyn_anti_recovery_cmds_count'] += 1
            for executed_cmd in proc.get('commands_executed', []):
                for cmd in ANTI_RECOVERY_CMDS:
                    if cmd in executed_cmd.lower():
                        features['dyn_anti_recovery_cmds_count'] += 1

        if total_api_calls > 0:
            features['dyn_crypto_api_ratio'] = dyn_crypto_count / total_api_calls
            features['dyn_file_api_ratio']   = dyn_file_api_count / total_api_calls

        # ── BƯỚC 2: File System Pattern ───────────────────────────────────────
        # Priority 1: CAPE summary (format chuẩn)
        files_written = summary.get('file_written', [])
        files_moved   = summary.get('file_moved', [])

        # Priority 2: Custom format (file_system block)
        if not files_written and not files_moved:
            file_system   = data.get('file_system', {})
            files_written = file_system.get('files_created', [])

        # Priority 3: Suy ra từ API calls
        if not files_written and not files_moved:
            logger.debug("Không tìm thấy file lists trong JSON, dùng API-derived counts.")
            files_written = ['_api_'] * api_derived_write
            files_moved   = ['_api_'] * api_derived_rename

        # Chuẩn hóa files_moved (Cuckoo lưu là list [src, dst])
        norm_moved = []
        for entry in files_moved:
            if isinstance(entry, list) and len(entry) > 0:
                norm_moved.append(str(entry[-1]))
            else:
                norm_moved.append(str(entry))

        all_touched_files = list(files_written) + norm_moved

        features['dyn_file_write_count']  = len(files_written)
        features['dyn_file_rename_count'] = len(files_moved)

        total_file_ops = len(all_touched_files)
        features['dyn_write_burst_score'] = total_file_ops / duration

        if total_file_ops > 0:
            features['dyn_rename_ratio'] = len(files_moved) / total_file_ops

        # Spread Analysis: Directory + Extension
        dirs_touched       = set()
        extensions_touched = set()
        suspicious_ext_count = 0

        for item in all_touched_files:
            path_str = str(item)
            if path_str == '_api_':
                continue
            dirs_touched.add(os.path.dirname(path_str).lower())
            ext = os.path.splitext(path_str)[1].lower()
            if ext:
                extensions_touched.add(ext)
                if ext in SUSPICIOUS_EXTENSIONS:
                    suspicious_ext_count += 1

        # Priority 2b: custom format files_modified_extensions
        if not extensions_touched:
            file_system = data.get('file_system', {})
            for ext in file_system.get('files_modified_extensions', []):
                ext_lower = ext.lower()
                extensions_touched.add(ext_lower)
                if ext_lower in SUSPICIOUS_EXTENSIONS:
                    suspicious_ext_count += 1
                    total_file_ops = max(total_file_ops, 1)

        # Priority 2c: encryption_activity block (custom format)
        enc = data.get('encryption_activity', {})
        if enc.get('volume_shadow_copies_deleted', False):
            features['dyn_anti_recovery_cmds_count'] += 1
        for api in enc.get('api_calls', []):
            api_lower = api.lower()
            if any(c in api_lower for c in CRYPTO_APIS):
                dyn_crypto_count += 1
                total_api_calls  += 1

        features['dyn_unique_dirs_touched']       = len(dirs_touched)
        features['dyn_file_type_diversity']        = len(extensions_touched)
        features['dyn_suspicious_extension_count'] = suspicious_ext_count

        if total_file_ops > 0:
            features['dyn_suspicious_ext_ratio'] = suspicious_ext_count / total_file_ops
            features['dyn_dirs_ratio']           = len(dirs_touched)    / total_file_ops

        # Tính lại crypto ratio nếu có thêm từ encryption_activity
        if total_api_calls > 0:
            features['dyn_crypto_api_ratio'] = dyn_crypto_count / total_api_calls

        # ── BƯỚC 3: Registry Activity ─────────────────────────────────────────
        reg_written = summary.get('regkey_written', [])
        reg_deleted = summary.get('regkey_deleted', [])
        features['dyn_registry_modified_count'] = len(reg_written) + len(reg_deleted)

        logger.debug(f"Dynamic features extracted: {features}")

    except Exception as e:
        logger.error(f"Lỗi khi xử lý file log động: {e}")

    return features

if __name__ == "__main__":
    logger.info("Features Module (Research-Level) cho Ransomware đã sẵn sàng.")
