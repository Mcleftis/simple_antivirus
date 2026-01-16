import hashlib
import time
import os
import requests

#Settings
API_KEY = 'your_API_key'  
TARGET_EXTENSIONS = ('.exe', '.dll', '.bat', '.msi', '.ps1', '.vbs') #poia arxeia einai epikindyna

def get_hash(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return None

def check_virus_total(file_hash):
    headers = {"x-apikey": API_KEY}
    response = requests.get(f'https://www.virustotal.com/api/v3/files/{file_hash}', headers=headers)
    
    if response.status_code == 200:
        stats = response.json()['data']['attributes']['last_analysis_stats']
        return stats['malicious']
    elif response.status_code == 404:
        return -1 #agnwsto arxeio
    elif response.status_code == 429:
        return -99 #xtyphsame to orio gia dwrean
    return 0

def smart_scan(folder):
    print(f" SMART SCANNING: {folder}")
    print("Looking only for executable files (.exe, .dll, etc.)")
    print("-" * 50)
    
    count = 0
    
    for root, _, files in os.walk(folder):
        for name in files:
            #filtro 1: einai ektlesimo?
            if name.lower().endswith(TARGET_EXTENSIONS):
                file_path = os.path.join(root, name)
                count += 1
                
                #filtro 2:orio hmeras
                if count > 500:
                    print("Daily Limit Reached (500 files). Stopping.")
                    return

                print(f"[{count}] Checking: {name} ... ", end="", flush=True)
                
                #ypologismos hash
                f_hash = get_hash(file_path)
                if not f_hash:
                    print("Skipped (Access Denied)")
                    continue

                #Erwthsh sto Cloud
                malicious_score = check_virus_total(f_hash)

                if malicious_score > 0:
                    print(f"INFECTED! ({malicious_score} Engines)")
                elif malicious_score == -1:
                    print(f"Unknown (New file)")
                elif malicious_score == -99:
                    print(f"\nAPI Limit Reached. Waiting 60s...")
                    time.sleep(60) #anexoume deny, perimenoume
                else:
                    print(f"Clean")

                #Stamatame ligo gia to dwrean api
                time.sleep(16) 

if __name__ == "__main__":
    #skanaroume ta downloads th noumero ena phgh iwn
    user_home = os.path.expanduser("~")
    downloads_path = os.path.join(user_home, "Downloads")
    
    if os.path.exists(downloads_path):
        smart_scan(downloads_path)
    else:
        print("Downloads folder not found.")