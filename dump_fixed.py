# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'a.py'
# Bytecode version: 3.14rc3 (3627)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

"""
XBOX CODE FETCHER + VALIDATOR - TURBO EDITION (FULLY FIXED)
Maximale Parallelisierung für Speed mit funktionierendem Validator!
Login-Logik EXAKT vom funktionierenden Standalone-Checker übernommen.
Mit HWID Lizenz-System!
"""
import requests
import re
import json
import time
import random
import string
import os
import sys
import queue
import ctypes
import threading
import uuid
import hashlib
import platform
import subprocess
from datetime import datetime
from typing import Optional, Tuple, List, Dict
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from colorama import init, Fore, Style
init(autoreset=True)
sys.dont_write_bytecode = True
print_lock = Lock()
results_lock = Lock()
LICENSE_URL = 'https://gist.githubusercontent.com/decxda/d7e741db93e986a92cd407cd8e96857a/raw/licenses.json'
PLAN_LIMITS = {'FREE': {'max_accounts': 5, 'max_threads': 2, 'max_codes': 50}, 'BASIC': {'max_accounts': 20, 'max_threads': 5, 'max_codes': 500}, 'PRO': {'max_accounts': 100, 'max_threads': 15, 'max_codes': 0}, 'PREMIUM': {'max_accounts': 0, 'max_threads': 0, 'max_codes': 0}}

def get_hwid():
    """Generate unique Hardware ID based on system information"""
    try:
        hwid_data = ''
        if platform.system() == 'Windows':
            try:
                output = subprocess.check_output('wmic csproduct get uuid', shell=True, stderr=subprocess.DEVNULL)
                hwid_data += output.decode().split('\n')[1].strip()
            except:
                pass
            try:
                output = subprocess.check_output('wmic bios get serialnumber', shell=True, stderr=subprocess.DEVNULL)
                hwid_data += output.decode().split('\n')[1].strip()
            except:
                pass
        elif platform.system() == 'Linux':
            try:
                with open('/etc/machine-id', 'r') as f:
                    hwid_data += f.read().strip()
            except:
                pass
            try:
                output = subprocess.check_output('cat /sys/class/dmi/id/product_uuid', shell=True, stderr=subprocess.DEVNULL)
                hwid_data += output.decode().strip()
            except:
                pass
        elif platform.system() == 'Darwin':
            try:
                output = subprocess.check_output('ioreg -rd1 -c IOPlatformExpertDevice | grep -E \'(IOPlatformUUID)\'', shell=True, stderr=subprocess.DEVNULL)
                hwid_data += output.decode().strip()
            except:
                pass
        
        if not hwid_data:
            import socket
            hwid_data = socket.gethostname() + str(uuid.getnode())
        
        hwid_data += platform.node() + platform.machine()
        hwid_hash = hashlib.sha256(hwid_data.encode()).hexdigest()[:32].upper()
        return hwid_hash
    except Exception as e:
        hwid_data = str(uuid.getnode()) + platform.node()
        hwid_hash = hashlib.sha256(hwid_data.encode()).hexdigest()[:32].upper()
        return hwid_hash

def fetch_licenses(url):
    """Fetch license data from remote URL (GitHub Gist, etc.)"""
    try:
        cache_buster = int(time.time())
        url_with_cache_buster = f'{url}?_={cache_buster}'
        headers = {'Cache-Control': 'no-cache, no-store, must-revalidate', 'Pragma': 'no-cache', 'Expires': '0'}
        response = requests.get(url_with_cache_buster, headers=headers, timeout=10)
        if response.status_code == 200:
            if not response.text or response.text.strip() == '':
                return None
            data = response.json()
            return data
        return None
    except Exception as e:
        return None

def check_license(hwid, licenses_data):
    """Check if HWID is licensed and return license info"""
    if not licenses_data or 'licenses' not in licenses_data:
        return None
    
    for license_entry in licenses_data['licenses']:
        if license_entry.get('hwid', '').upper() == hwid.upper():
            expiry_str = license_entry.get('expiry', '')
            if expiry_str:
                try:
                    expiry_date = datetime.strptime(expiry_str, '%Y-%m-%d')
                    if datetime.now() > expiry_date:
                        return {'status': 'EXPIRED', 'plan': license_entry.get('plan', 'FREE')}
                except:
                    pass
            return {'status': 'VALID', 'plan': license_entry.get('plan', 'FREE'), 'name': license_entry.get('name', 'User'), 'expiry': expiry_str}
    
    return None

def display_license_status(license_info, hwid):
    """Display license status in a nice format"""
    print(f'\n{Fore.CYAN}{'============================================================'}')
    print(f'🔑 LICENSE STATUS{Style.RESET_ALL}')
    print(f'{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}')
    print(f'{Fore.WHITE}  HWID: {Fore.YELLOW}{hwid}{Style.RESET_ALL}')
    if license_info is None:
        print(f'{Fore.RED}  Status: ❌ NOT LICENSED{Style.RESET_ALL}')
        print(f'{Fore.YELLOW}  Contact admin to get a license!{Style.RESET_ALL}')
        print(f'{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}\n')
        return False
    else:
        if license_info['status'] == 'EXPIRED':
            print(f'{Fore.RED}  Status: ⏰ LICENSE EXPIRED{Style.RESET_ALL}')
            print(f'{Fore.YELLOW}  Plan was: {license_info['plan']}{Style.RESET_ALL}')
            print(f'{Fore.YELLOW}  Contact admin to renew!{Style.RESET_ALL}')
            print(f'{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}\n')
            return False
        else:
            plan = license_info['plan']
            limits = PLAN_LIMITS.get(plan, PLAN_LIMITS['FREE'])
            print(f'{Fore.GREEN}  Status: ✅ LICENSED{Style.RESET_ALL}')
            print(f'{Fore.CYAN}  Name: {license_info.get('name', 'User')}{Style.RESET_ALL}')
            print(f'{Fore.MAGENTA}  Plan: {plan}{Style.RESET_ALL}')
            if license_info.get('expiry'):
                print(f'{Fore.YELLOW}  Expires: {license_info['expiry']}{Style.RESET_ALL}')
            print(f'{Fore.WHITE}  Limits:{Style.RESET_ALL}')
            if limits['max_accounts'] == 0:
                print(f'{Fore.GREEN}    - Accounts: Unlimited{Style.RESET_ALL}')
            else:
                print(f'{Fore.GREEN}    - Accounts: {limits['max_accounts']}{Style.RESET_ALL}')
            if limits['max_threads'] == 0:
                print(f'{Fore.GREEN}    - Threads: Unlimited{Style.RESET_ALL}')
            else:
                print(f'{Fore.GREEN}    - Threads: {limits['max_threads']}{Style.RESET_ALL}')
            if limits['max_codes'] == 0:
                print(f'{Fore.GREEN}    - Codes: Unlimited{Style.RESET_ALL}')
            else:
                print(f'{Fore.GREEN}    - Codes: {limits['max_codes']}{Style.RESET_ALL}')
            print(f'{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}\n')
            return True

def apply_license_limits(license_info, accounts, codes, threads):
    """Apply license limits to accounts, codes, and threads"""
    plan = license_info.get('plan', 'FREE')
    limits = PLAN_LIMITS.get(plan, PLAN_LIMITS['FREE'])
    if limits['max_accounts'] > 0 and len(accounts) > limits['max_accounts']:
        print(f'{Fore.YELLOW}⚠️ License limit: Using only {limits['max_accounts']} accounts{Style.RESET_ALL}')
        accounts = accounts[:limits['max_accounts']]
    if limits['max_codes'] > 0 and len(codes) > limits['max_codes']:
        print(f'{Fore.YELLOW}⚠️ License limit: Using only {limits['max_codes']} codes{Style.RESET_ALL}')
        codes = codes[:limits['max_codes']]
    if limits['max_threads'] > 0 and threads > limits['max_threads']:
        print(f'{Fore.YELLOW}⚠️ License limit: Using only {limits['max_threads']} threads{Style.RESET_ALL}')
        threads = limits['max_threads']
    return (accounts, codes, threads)

def safe_print(message):
    """Thread-safe printing"""
    with print_lock:
        print(message)

def print_colored(text, color):
    """Print colored text"""
    print(f'{color}{text}{Style.RESET_ALL}')

def print_banner():
    """Print cool banner"""
    banner = f"""
{Fore.CYAN}{'============================================================'}
🚀 XBOX CODE FETCHER + VALIDATOR - TURBO EDITION 🚀
{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}
{Fore.YELLOW}Parallel Fetch + Working Validator + HWID License System{Style.RESET_ALL}
{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}
"""
    print(banner)

def fetch_oauth_tokens(email, password, proxy=None):
    """Fetch OAuth tokens from Microsoft account"""
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    try:
        response = session.post('https://login.live.com/oauth20_token.srf', data={'grant_type': 'password', 'client_id': '00000000402b5328', 'scope': 'service::user.auth.xboxlive.com::MBI_SSL', 'username': email, 'password': password})
        if response.status_code == 200:
            data = response.json()
            return data.get('access_token')
    except:
        pass
    return None

def fetch_login(email, password, proxy=None):
    """Login and get Xbox Live token"""
    access_token = fetch_oauth_tokens(email, password, proxy)
    if not access_token:
        return None
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    try:
        xbl_response = session.post('https://user.auth.xboxlive.com/user/authenticate', json={'RelyingParty': 'http://auth.xboxlive.com', 'TokenType': 'JWT', 'Properties': {'AuthMethod': 'RPS', 'SiteName': 'user.auth.xboxlive.com', 'RpsTicket': access_token}})
        if xbl_response.status_code == 200:
            xbl_data = xbl_response.json()
            xbl_token = xbl_data.get('Token')
            user_hash = xbl_data['DisplayClaims']['xui'][0]['uhs']
            xsts_response = session.post('https://xsts.auth.xboxlive.com/xsts/authorize', json={'RelyingParty': 'http://xboxlive.com', 'TokenType': 'JWT', 'Properties': {'UserTokens': [xbl_token], 'SandboxId': 'RETAIL'}})
            if xsts_response.status_code == 200:
                xsts_data = xsts_response.json()
                xsts_token = xsts_data.get('Token')
                return (xsts_token, user_hash)
    except:
        pass
    return None

def get_xbox_tokens(email, password, proxy=None):
    """Get Xbox Live tokens for authentication"""
    result = fetch_login(email, password, proxy)
    if result:
        return result
    return (None, None)

def fetch_codes_from_xbox(xsts_token, user_hash, proxy=None):
    """Fetch codes from Xbox account"""
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    headers = {'Authorization': f'XBL3.0 x={user_hash};{xsts_token}', 'Content-Type': 'application/json'}
    try:
        response = session.get('https://emerald.xboxservices.com/xboxcomfd/experimentation/experimentAssignments', headers=headers)
        codes = []
        if response.status_code == 200:
            data = response.json()
            for item in data.get('ExperimentAssignments', []):
                if 'Code' in item:
                    codes.append(item['Code'])
        return codes
    except:
        return []

def fetch_account_worker(email, password, index, total, proxy=None):
    """Worker function to fetch codes from a single account"""
    safe_print(f'{Fore.CYAN}[{index}/{total}] Fetching: {email}{Style.RESET_ALL}')
    (xsts_token, user_hash) = get_xbox_tokens(email, password, proxy)
    if xsts_token:
        codes = fetch_codes_from_xbox(xsts_token, user_hash, proxy)
        safe_print(f'{Fore.GREEN}[{index}/{total}] ✅ {email}: {len(codes)} codes{Style.RESET_ALL}')
        return codes
    else:
        safe_print(f'{Fore.RED}[{index}/{total}] ❌ {email}: Login failed{Style.RESET_ALL}')
        return []

def generate_reference_id():
    """Generate reference ID for code validation"""
    return ''.join((random.choices(string.ascii_uppercase + string.digits, k=16)))

def get_random_proxy(proxies):
    """Get random proxy from list"""
    if proxies:
        return random.choice(proxies)
    return None

def read_proxies(filename):
    """Read proxies from file"""
    try:
        with open(filename, 'r') as f:
            proxies = [line.strip() for line in f if line.strip()]
        return proxies
    except:
        return []

def ask_proxy_settings():
    """Ask user for proxy settings"""
    print(f'{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}')
    print(f'{Fore.WHITE}Use proxies? (y/n): {Style.RESET_ALL}', end='')
    use_proxies = input().strip().lower()
    if use_proxies == 'y':
        proxies = read_proxies('proxies.txt')
        if proxies:
            print(f'{Fore.GREEN}✅ Loaded {len(proxies)} proxies{Style.RESET_ALL}')
            return proxies
        else:
            print(f'{Fore.RED}❌ No proxies found in proxies.txt{Style.RESET_ALL}')
            return None
    return None

def login_microsoft_account(email, password, proxy=None):
    """Login to Microsoft account and get Xbox tokens"""
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    try:
        response = session.post('https://login.live.com/oauth20_token.srf', data={'grant_type': 'password', 'client_id': '00000000402b5328', 'scope': 'service::user.auth.xboxlive.com::MBI_SSL', 'username': email, 'password': password}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            access_token = data.get('access_token')
            if access_token:
                xbl_response = session.post('https://user.auth.xboxlive.com/user/authenticate', json={'RelyingParty': 'http://auth.xboxlive.com', 'TokenType': 'JWT', 'Properties': {'AuthMethod': 'RPS', 'SiteName': 'user.auth.xboxlive.com', 'RpsTicket': access_token}}, timeout=10)
                if xbl_response.status_code == 200:
                    xbl_data = xbl_response.json()
                    xbl_token = xbl_data.get('Token')
                    user_hash = xbl_data['DisplayClaims']['xui'][0]['uhs']
                    return (xbl_token, user_hash)
    except:
        pass
    return (None, None)

def get_auth_token(xbl_token, user_hash, proxy=None):
    """Get XSTS authentication token"""
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    try:
        response = session.post('https://xsts.auth.xboxlive.com/xsts/authorize', json={'RelyingParty': 'http://xboxlive.com', 'TokenType': 'JWT', 'Properties': {'UserTokens': [xbl_token], 'SandboxId': 'RETAIL'}}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get('Token')
    except:
        pass
    return None

def get_store_cart_state(auth_token, user_hash, proxy=None):
    """Get store cart state"""
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    headers = {'Authorization': f'XBL3.0 x={user_hash};{auth_token}', 'Content-Type': 'application/json'}
    try:
        response = session.get('https://emerald.xboxservices.com/xboxcomfd/cart', headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

def prepare_redeem_api_call(code, auth_token, user_hash, reference_id, cart_state, proxy=None):
    """Prepare API call for code redemption"""
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    headers = {'Authorization': f'XBL3.0 x={user_hash};{auth_token}', 'Content-Type': 'application/json', 'X-XBL-Contract-Version': '2'}
    payload = {'code': code, 'referenceId': reference_id}
    return (session, headers, payload)

def validate_code_primary(code, auth_token, user_hash, reference_id, proxy=None):
    """Primary validation method for codes"""
    session = requests.Session()
    if proxy:
        session.proxies = {'http': proxy, 'https': proxy}
    headers = {'Authorization': f'XBL3.0 x={user_hash};{auth_token}', 'Content-Type': 'application/json'}
    payload = {'code': code, 'referenceId': reference_id}
    try:
        response = session.post('https://emerald.xboxservices.com/xboxcomfd/redeem', json=payload, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            if any((kw in str(data).lower() for kw in ['success', 'redeemed', 'valid'])):
                return 'VALID'
            if any((kw in str(data).lower() for kw in ['payment', 'card', 'billing'])):
                return 'VALID_REQUIRES_CARD'
            if any((kw in str(data).lower() for kw in ['region', 'location', 'country'])):
                return 'REGION_LOCKED'
            if any((kw in str(data).lower() for kw in ['invalid', 'expired', 'used'])):
                return 'INVALID'
        elif response.status_code == 400:
            return 'INVALID'
        elif response.status_code == 403:
            return 'REGION_LOCKED'
    except:
        pass
    return 'UNKNOWN'

def validate_code(code, auth_token, user_hash, proxy=None):
    """Validate a single code"""
    reference_id = generate_reference_id()
    result = validate_code_primary(code, auth_token, user_hash, reference_id, proxy)
    return result

def process_code_check(account, code, result_files, results_count, processed_codes_lock, processed_codes, proxy=None):
    """Process a single code check"""
    email = account[0]
    password = account[1]
    (xbl_token, user_hash) = login_microsoft_account(email, password, proxy)
    if not xbl_token:
        return None
    auth_token = get_auth_token(xbl_token, user_hash, proxy)
    if not auth_token:
        return None
    result = validate_code(code, auth_token, user_hash, proxy)
    with processed_codes_lock:
        if code not in processed_codes:
            processed_codes.add(code)
            with results_lock:
                results_count[result] = results_count.get(result, 0) + 1
                with open(result_files[result], 'a') as f:
                    f.write(f'{code}\n')
    return result

def process_codes_for_account(account, codes_queue, result_files, results_count, processed_codes_lock, processed_codes, total_codes, prepare_redeem_executor, proxy, rate_limited_accounts):
    """Process codes for a single account"""
    email = account[0]
    password = account[1]
    (xbl_token, user_hash) = login_microsoft_account(email, password, proxy)
    if not xbl_token:
        safe_print(f'{Fore.RED}❌ {email}: Login failed{Style.RESET_ALL}')
        return
    auth_token = get_auth_token(xbl_token, user_hash, proxy)
    if not auth_token:
        safe_print(f'{Fore.RED}❌ {email}: Auth failed{Style.RESET_ALL}')
        return
    codes_checked = 0
    while not codes_queue.empty():
        try:
            code = codes_queue.get_nowait()
        except queue.Empty:
            break
        with processed_codes_lock:
            if code in processed_codes:
                codes_queue.task_done()
                continue
        result = validate_code(code, auth_token, user_hash, proxy)
        with processed_codes_lock:
            if code not in processed_codes:
                processed_codes.add(code)
                with results_lock:
                    results_count[result] = results_count.get(result, 0) + 1
                    with open(result_files[result], 'a') as f:
                        f.write(f'{code}\n')
        codes_checked += 1
        progress = len(processed_codes) / total_codes * 100
        safe_print(f'{Fore.CYAN}[{email}] {result}: {code} ({progress:.1f}%){Style.RESET_ALL}')
        codes_queue.task_done()
        time.sleep(0.1)
    safe_print(f'{Fore.GREEN}✅ {email}: Checked {codes_checked} codes{Style.RESET_ALL}')

def read_accounts(filename):
    """Read accounts from file"""
    try:
        with open(filename, 'r') as f:
            accounts = []
            for line in f:
                line = line.strip()
                if ':' in line:
                    parts = line.split(':', 1)
                    accounts.append((parts[0], parts[1]))
        return accounts
    except:
        return []

def main():
    """Main function"""
    print_banner()
    hwid = get_hwid()
    safe_print(f'{Fore.YELLOW}🔍 Checking license...{Style.RESET_ALL}')
    licenses_data = fetch_licenses(LICENSE_URL)
    license_info = check_license(hwid, licenses_data)
    if not display_license_status(license_info, hwid):
        safe_print(f'{Fore.RED}❌ No valid license found{Style.RESET_ALL}')
        input(f'{Fore.YELLOW}Press Enter to exit...{Style.RESET_ALL}')
        return
    accounts = read_accounts('accounts.txt')
    if not accounts:
        print(f'{Fore.RED}❌ No accounts in accounts.txt{Style.RESET_ALL}')
        print(f'{Fore.YELLOW}Create accounts.txt with format: email:password{Style.RESET_ALL}')
        return
    print(f'{Fore.CYAN}📂 Loaded {len(accounts)} accounts{Style.RESET_ALL}')
    if license_info:
        accounts, _, _ = apply_license_limits(license_info, accounts, [], 1)
    proxies = ask_proxy_settings()
    print(f'\n{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}')
    print(f'{Fore.WHITE}  [1] Fetch only')
    print('  [2] Validate only (codes.txt)')
    print(f'  [3] Fetch + Validate COMBO{Style.RESET_ALL}')
    print(f'{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}\n')
    choice = input(f'{Fore.YELLOW}Choice (1/2/3): {Style.RESET_ALL}').strip()
    all_codes = []
    if choice in ['1', '3']:
        print(f'\n{Fore.CYAN}{'============================================================'}')
        print(f'🚀 FETCHING CODES (parallel){Style.RESET_ALL}')
        print(f'{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}\n')
        fetch_threads = min(20, len(accounts))
        if license_info:
            _, _, fetch_threads = apply_license_limits(license_info, [], [], fetch_threads)
        start = time.time()
        with ThreadPoolExecutor(max_workers=fetch_threads) as executor:
            futures = {executor.submit(fetch_account_worker, email, pwd, i + 1, len(accounts)): i for i, (email, pwd) in enumerate(accounts)}
            for future in as_completed(futures):
                codes = future.result()
                all_codes.extend(codes)
        elapsed = time.time() - start
        print(f'\n{Fore.GREEN}✅ Fetched {len(all_codes)} codes in {elapsed:.1f}s{Style.RESET_ALL}')
        if all_codes:
            with open('codes.txt', 'w') as f:
                f.write('\n'.join(all_codes))
            print(f'{Fore.GREEN}💾 Saved to codes.txt{Style.RESET_ALL}\n')
    
    if choice in ['2', '3']:
        print(f'\n{Fore.CYAN}{'============================================================'}')
        print(f'🔍 VALIDATING CODES (queue-based like standalone checker){Style.RESET_ALL}')
        print(f'{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}\n')
        if choice == '2':
            try:
                with open('codes.txt', 'r') as f:
                    all_codes = [line.strip().split('|')[0].strip() for line in f if line.strip()]
            except:
                print(f'{Fore.RED}❌ codes.txt not found{Style.RESET_ALL}')
                return
        
        if not all_codes:
            print(f'{Fore.RED}❌ No codes to validate{Style.RESET_ALL}')
            return
        
        if license_info:
            _, all_codes, _ = apply_license_limits(license_info, [], all_codes, 1)
        
        print(f'{Fore.WHITE}📝 {len(all_codes)} codes to validate{Style.RESET_ALL}')
        if proxies:
            print(f'{Fore.GREEN}🌐 Using {len(proxies)} proxies{Style.RESET_ALL}')
        else:
            print(f'{Fore.YELLOW}⚠️ No proxies - using direct connection{Style.RESET_ALL}')
        print()
        
        max_threads = len(accounts)
        if license_info:
            plan = license_info.get('plan', 'FREE')
            plan_max = PLAN_LIMITS.get(plan, {}).get('max_threads', 0)
            if plan_max > 0:
                max_threads = min(max_threads, plan_max)
        
        while True:
            try:
                batch_size = int(input(f'{Fore.CYAN}Thread Count? (1-{max_threads}): {Style.RESET_ALL}'))
                if 1 <= batch_size <= max_threads:
                    break
                print(f'{Fore.RED}Please enter a number between 1 and {max_threads}{Style.RESET_ALL}')
            except ValueError:
                print(f'{Fore.RED}Please enter a valid number{Style.RESET_ALL}')
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_folder = f'results/check_{timestamp}'
        os.makedirs(results_folder, exist_ok=True)
        result_files = {'VALID': f'{results_folder}/valid_codes.txt', 'VALID_REQUIRES_CARD': f'{results_folder}/valid_cardrequired_codes.txt', 'INVALID': f'{results_folder}/invalid.txt', 'UNKNOWN': f'{results_folder}/unknown_codes.txt', 'REGION_LOCKED': f'{results_folder}/region_locked_codes.txt'}
        results_count = {status: 0 for status in result_files.keys()}
        for file_path in result_files.values():
            with open(file_path, 'a'):
                pass
        
        codes_queue = queue.Queue()
        for code in all_codes:
            codes_queue.put(code)
        
        print(f'Added {len(all_codes)} codes to the queue\n')
        processed_codes = set()
        processed_codes_lock = threading.Lock()
        rate_limited_accounts = []
        prepare_redeem_executor = ThreadPoolExecutor(max_workers=5)
        start = time.time()
        
        try:
            with ThreadPoolExecutor(max_workers=batch_size) as account_executor:
                account_futures = {account_executor.submit(process_codes_for_account, account, codes_queue, result_files, results_count, processed_codes_lock, processed_codes, len(all_codes), prepare_redeem_executor, get_random_proxy(proxies) if proxies else None, rate_limited_accounts): account for account in accounts}
                for future in as_completed(account_futures):
                    pass
        finally:
            prepare_redeem_executor.shutdown(wait=True)
        
        elapsed = time.time() - start
        print(f'\n{Fore.CYAN}{'============================================================'}')
        print(f'📊 RESULTS ({elapsed:.1f}s){Style.RESET_ALL}')
        print(f'{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}')
        print(f'{Fore.GREEN}  ✅ Valid: {results_count.get('VALID', 0)}{Style.RESET_ALL}')
        print(f'{Fore.YELLOW}  💳 Valid (Card Required): {results_count.get('VALID_REQUIRES_CARD', 0)}{Style.RESET_ALL}')
        print(f'{Fore.MAGENTA}  🌍 Region Locked: {results_count.get('REGION_LOCKED', 0)}{Style.RESET_ALL}')
        print(f'{Fore.RED}  ❌ Invalid: {results_count.get('INVALID', 0)}{Style.RESET_ALL}')
        print(f'{Fore.YELLOW}  ❓ Unknown: {results_count.get('UNKNOWN', 0)}{Style.RESET_ALL}')
        print(f'{Fore.CYAN}{'============================================================'}{Style.RESET_ALL}\n')
        
        with open(f'{results_folder}/summary.txt', 'w') as f:
            f.write(f'Code Check Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n')
            f.write('==================================================\n\n')
            f.write(f'Total Codes: {len(all_codes)}\n')
            f.write(f'Total Accounts: {len(accounts)}\n')
            f.write(f'Batch Size: {batch_size}\n')
            if proxies:
                f.write(f'Proxies Used: {len(proxies)}\n')
            f.write('\nFinal Results:\n')
            f.write('--------------------\n')
            f.write(f'Valid Codes: {results_count.get('VALID', 0)}\n')
            f.write(f'Valid (Requires Card): {results_count.get('VALID_REQUIRES_CARD', 0)}\n')
            f.write(f'Region Locked: {results_count.get('REGION_LOCKED', 0)}\n')
            f.write(f'Invalid: {results_count.get('INVALID', 0)}\n')
            f.write(f'Unknown: {results_count.get('UNKNOWN', 0)}\n')
        
        print(f'{Fore.GREEN}💾 Results saved to {results_folder}/{Style.RESET_ALL}')
        with open('codes.txt', 'w') as f:
            remaining_codes = [c for c in all_codes if c not in processed_codes]
            f.write('\n'.join(remaining_codes))
        
        if rate_limited_accounts:
            print(f'\n{Fore.YELLOW}Found {len(rate_limited_accounts)} rate-limited accounts.{Style.RESET_ALL}')
        
        print(f'\n{Fore.GREEN}🎉 DONE!{Style.RESET_ALL}\n')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f'\n{Fore.RED}❌ Interrupted{Style.RESET_ALL}')
        sys.exit(0)
