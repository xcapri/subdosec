import os
import json
import base64
import asyncio
import aiohttp
import requests
from .app_config import get_user_dir, load_env_vars, file_lock
from .utils import load_json_without_comments

def fetch_fingerprints(host_scan_prod, update):
    """Fetch fingerprints from API or load from cache if available (unless update is True)."""
    user_dir = get_user_dir()
    offline_fingerprint = os.path.join(user_dir, 'offinger.json')

    if update or not os.path.exists(offline_fingerprint):
        url = host_scan_prod.replace('/api/scan/cli', '/api/getfinger')
        if '/api/getfinger' not in url:
             pass
        try:
             response = requests.get(url, timeout=30)
             response.raise_for_status()

             data = response.json()

             with open(offline_fingerprint, 'w') as f:
                json.dump(data, f, indent=2)

             if update:
                print("Update successful")
                return

             return data
        except Exception:
             pass

    if os.path.exists(offline_fingerprint):
        with open(offline_fingerprint, 'r') as f:
            return json.load(f)
    return {'fingerprints': []}

async def undetect_site(siteinfo, apikey, host_scan_prod, mode):
    """Notify the server about undetected sites."""
    url = host_scan_prod.replace('/api/scan/cli', '/api/undetect/stored/cli')
    headers = {'Subdosec-Apikey': apikey}
    web_data_encoded = base64.b64encode(json.dumps(siteinfo.get('website_data')).encode('utf-8')).decode('utf-8')
    payload = {
        'web_data': web_data_encoded,
        'mode': mode
    }
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=payload) as response:
           return await response.json()

async def undetect_site_localy(siteinfo, path):
    siteinfo['website_data'].pop('response_body_base64', None)

    if not os.path.exists(path):
        os.makedirs(path)

    file_path = os.path.join(path, "undetect.json")

    with file_lock:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                    if not isinstance(data, list):
                        data = []
                except json.JSONDecodeError:
                    data = []
        else:
            data = []

        data.append(siteinfo['website_data'])

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)

async def vuln_site(siteinfo, fingerprint_id, apikey, host_scan_prod, mode):
    """Notify the server about undetected sites."""
    url = host_scan_prod.replace('/api/scan/cli', '/api/vuln/stored/cli')
    headers = {'Subdosec-Apikey': apikey}
    web_data_encoded = base64.b64encode(json.dumps(siteinfo).encode('utf-8')).decode('utf-8')
    payload = {
        'web_data': web_data_encoded,
        'mode': mode,
        'fingerprint_id': fingerprint_id
    }
   
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=payload) as response:
           data = await response.json()
           return data

async def save_local(w, fs, fid, o):
    save_path = os.path.join(o)
    
    if not os.path.exists(save_path):
        os.makedirs(save_path)

    file_name = f"{fs}_tko.txt"
    file_path = os.path.join(save_path, file_name)
    
    subdomain = w.get('subdomain', None)

    if subdomain:
        with file_lock:
            with open(file_path, 'a') as file:
                file.write(subdomain + '\n')
    else:
        print(f"No subdomain found in data.")

def check_fingerprint(p):
    try:
        _, _, _, host_scan_prod, _ = load_env_vars('public')
        fingerprints = fetch_fingerprints(host_scan_prod, False)

        output = []

        for fingerprint in fingerprints['fingerprints']:
            service = fingerprint['service']
            name = fingerprint['name']
            status = "[False Positive]" if fingerprint['status_fingerprint'] == 1 else "[Active]"

            entry = {
                "service": service,
                "name": name,
                "status": status
            }

            output.append(entry)

            if p == 1:
                print(f"{service} | {name} {status}")

        return output

    except Exception as e:
        print(f"[Error] : {e}")
        return []

def read_local_finger(file_path, host_scan_prod):
    cache_finger = fetch_fingerprints(host_scan_prod, False)
    cache_list = cache_finger.get("fingerprints", [])

    try:
        with open(file_path, 'r') as file:
            local_data = json.load(file)
            local_list = local_data.get("fingerprints", [])

            max_fid = max([item["fid"] for item in cache_list], default=0)
            existing_fids = {item["fid"] for item in cache_list}

            for item in local_list:
                if item["fid"] in existing_fids:
                    max_fid += 1 
                    item["fid"] = max_fid
                cache_list.append(item)

            return {"fingerprints": cache_list}

    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found. Try using fingerprint form server.")
        return cache_finger
    except json.JSONDecodeError:
        print(f"Error: The file at {file_path} is not a valid JSON file. Try using fingerprint form server.")
        return cache_finger

def submit_fingerprint(file_path):
    data = load_json_without_comments(file_path)
    if not data:
        return

    try:
        _, _, _, host_scan_prod, _ = load_env_vars('public')
        url = host_scan_prod.replace('/api/scan/cli', '/api/importFingerprint')
        
        print(f"[Info] Submitting fingerprint...")
                
        response = requests.post(url, headers={"Content-Type": "application/json"}, json=data, timeout=30)
        
        if response.status_code == 200 or response.status_code == 201:
             print(f"[Success] Fingerprint submitted successfully!")
        else:
             print(f"[Error] Failed to submit fingerprint. Status Code: {response.status_code}")

    except Exception as e:
        print(f"[Error] Submission failed: {e}")
