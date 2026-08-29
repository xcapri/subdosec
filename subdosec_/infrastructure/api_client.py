import os
import json
import base64
import requests
import aiohttp
from typing import Dict, List, Any

from ..core.ports import FingerprintRepository, ScanClient, LocalStorage
from ..shared import colors
from ..shared.utils import load_json_without_comments


class ApiClient(FingerprintRepository, ScanClient):
    def __init__(self, storage: LocalStorage):
        self.storage = storage

    # --- FingerprintRepository Implementation ---

    def fetch_fingerprints(self, host_scan_prod: str, update: bool) -> Dict[str, List[Dict[str, Any]]]:
        """Fetch fingerprints from API or load from cache if available (unless update is True)."""
        user_dir = self.storage.get_user_dir()
        offline_fingerprint = os.path.join(user_dir, 'offinger.json')

        if update or not os.path.exists(offline_fingerprint):
            url = host_scan_prod.replace('/api/scan/cli', '/api/getfinger')
            try:
                 response = requests.get(url, timeout=30)
                 response.raise_for_status()

                 data = response.json()

                 with open(offline_fingerprint, 'w') as f:
                    json.dump(data, f, indent=2)

                 if update:
                    print("Update successful")
                    return data

                 return data
            except Exception:
                 pass

        if os.path.exists(offline_fingerprint):
            with open(offline_fingerprint, 'r') as f:
                return json.load(f)
        return {'fingerprints': []}

    def read_local_fingerprints(self, file_path: str, host_scan_prod: str) -> Dict[str, List[Dict[str, Any]]]:
        cache_finger = self.fetch_fingerprints(host_scan_prod, False)
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
            print(f"Error: The file at {file_path} was not found. Try using fingerprint from server.")
            return cache_finger
        except json.JSONDecodeError:
            print(f"Error: The file at {file_path} is not a valid JSON file. Try using fingerprint from server.")
            return cache_finger

    def submit_fingerprint(self, file_path: str) -> bool:
        data = load_json_without_comments(file_path)
        if not data:
            return False

        try:
            _, _, _, host_scan_prod, _ = self.storage.load_env_vars('public')
            url = host_scan_prod.replace('/api/scan/cli', '/api/importFingerprint')
            
            print(colors.info("Submitting fingerprint..."))
                    
            response = requests.post(url, headers={"Content-Type": "application/json"}, json=data, timeout=30)
            
            if response.status_code in (200, 201):
                 print(colors.success("Fingerprint submitted successfully!"))
                 return True
            else:
                 print(colors.error(f"Failed to submit fingerprint. Status Code: {response.status_code}"))
                 return False

        except Exception as e:
            print(colors.error(f"Submission failed: {e}"))
            return False

    # --- ScanClient Implementation ---

    def check_match(
        self,
        target: str,
        mode: str,
        title: str,
        status_code: int,
        body_match: bool,
        redirect_url: str,
        fingerprint_encoded: str,
        apikey: str,
        host_scan: str
    ) -> Dict[str, Any]:
        """Query the local scan server to check if fingerprint rules match."""
        scan_payload = {
            'target': target,
            'mode': mode,
            'title_fu': title,
            'sc_fu': status_code,
            'body_fu': body_match,
            'redirect_url': redirect_url,
            'fingerprint_new': fingerprint_encoded,
        }
        scan_response = requests.post(host_scan, headers={'Subdosec-Apikey': apikey}, json=scan_payload, timeout=30)
        return scan_response.json()

    async def notify_vuln(
        self,
        web_data: Dict[str, Any],
        fingerprint_id: int,
        apikey: str,
        host_scan_prod: str,
        mode: str
    ) -> Dict[str, Any]:
        """Notify production server of a vulnerability detection."""
        url = host_scan_prod.replace('/api/scan/cli', '/api/vuln/stored/cli')
        headers = {'Subdosec-Apikey': apikey}
        web_data_encoded = base64.b64encode(json.dumps(web_data).encode('utf-8')).decode('utf-8')
        payload = {
            'web_data': web_data_encoded,
            'mode': mode,
            'fingerprint_id': fingerprint_id
        }
       
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
               return await response.json()

    async def notify_undetect(
        self,
        site_info: Dict[str, Any],
        apikey: str,
        host_scan_prod: str,
        mode: str
    ) -> Dict[str, Any]:
        """Notify production server of an undetected site."""
        url = host_scan_prod.replace('/api/scan/cli', '/api/undetect/stored/cli')
        headers = {'Subdosec-Apikey': apikey}
        
        web_data = site_info.get('website_data', {})
        web_data_encoded = base64.b64encode(json.dumps(web_data).encode('utf-8')).decode('utf-8')
        payload = {
            'web_data': web_data_encoded,
            'mode': mode
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=payload) as response:
               return await response.json()
