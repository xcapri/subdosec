import os
import json
from typing import Dict, Any
from dotenv import load_dotenv, set_key

from ..core.ports import LocalStorage
from ..shared.utils import file_lock


class FileStorage(LocalStorage):
    def get_user_dir(self) -> str:
        """Get the user-specific directory for configuration and data."""
        path = os.path.join(os.path.expanduser("~"), ".subdosec")
        if not os.path.exists(path):
            os.makedirs(path)
        return path

    def init_key(self, apikey: str) -> None:
        """Initialize the API key in the .env file."""
        user_dir = self.get_user_dir()
        env_file = os.path.join(user_dir, '.env')
        
        # Create empty .env if not exists
        if not os.path.exists(env_file):
            open(env_file, 'a').close()

        load_dotenv(dotenv_path=env_file)
        set_key(env_file, 'APIKEY', apikey)
        print(f"API key has been written to {env_file}")

    def load_env_vars(self, mode: str) -> tuple:
        """Load environment variables based on the mode."""
        user_dir = self.get_user_dir()
        env_file = os.path.join(user_dir, '.env')
        
        defaults = {
            "PUBLIC_API_KEY": "feaf1cc1-1199-4eb5-864d-b4cec1526c71",
            "OUTPUT_SCAN_PRIV": "https://subdosec.vulnshot.com/result/priv/",
            "OUTPUT_SCAN_PUB": "https://subdosec.vulnshot.com/result/pub/",
            "PROD_SCAN_API_HOST": "https://sscan.vulnshot.com/api/scan/cli",
            "SCAN_API_HOST": "http://127.0.0.1:3000/local/scan",
            "PORT": "3000",
            "SIGNUP_URL": "https://subdosec.vulnshot.com/signup"
        }

        # Ensure .env exists
        if not os.path.exists(env_file):
            with open(env_file, 'w') as f:
                for key, value in defaults.items():
                    f.write(f"{key}={value}\n")
        
        # Load and check for missing keys
        load_dotenv(dotenv_path=env_file)
        
        current_vars = {}
        with open(env_file, 'r') as f:
            for line in f:
                 if '=' in line:
                     key = line.split('=')[0].strip()
                     current_vars[key] = True

        with open(env_file, 'a') as f:
            for key, value in defaults.items():
                if key not in current_vars and not os.getenv(key):
                     f.write(f"{key}={value}\n")
        
        # Reload to get new defaults
        load_dotenv(dotenv_path=env_file, override=True)

        apikey = os.getenv('APIKEY') if mode == 'private' else os.getenv('PUBLIC_API_KEY')
        output_scan = os.getenv('OUTPUT_SCAN_PRIV') if mode == 'private' else os.getenv('OUTPUT_SCAN_PUB')
        
        scan_host_env = os.getenv('SCAN_API_HOST', defaults["SCAN_API_HOST"])
        port_env = os.getenv('PORT', defaults["PORT"])
        
        host_scan = scan_host_env.replace('3000', port_env)
        host_scan_prod = os.getenv('PROD_SCAN_API_HOST', defaults["PROD_SCAN_API_HOST"])
        node_port = port_env 

        if not all([host_scan, output_scan]):
            raise ValueError("Missing required environment variables.")
        
        if mode == 'private' and not apikey:
            signup_url = os.getenv('SIGNUP_URL', 'https://subdosec.vulnshot.com/')
            raise ValueError(f"Create a password & apikey first at {signup_url}.\nThen run `subdosec -initkey your-key`")
        
        return apikey, output_scan or "", host_scan, host_scan_prod, node_port

    async def save_vuln_local(
        self,
        web_data: Dict[str, Any],
        service: str,
        fingerprint_id: int,
        output_dir: str
    ) -> None:
        """Save vulnerable scan results to a local file."""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        file_name = f"{service}_tko.txt"
        file_path = os.path.join(output_dir, file_name)
        
        subdomain = web_data.get('subdomain', None)

        if subdomain:
            with file_lock:
                with open(file_path, 'a') as file:
                    file.write(subdomain + '\n')
        else:
            print(f"No subdomain found in data.")

    async def save_undetect_local(
        self,
        site_info: Dict[str, Any],
        output_dir: str
    ) -> None:
        """Save undetected scan results to a local file."""
        site_info_copy = dict(site_info)
        if 'website_data' in site_info_copy:
            site_info_copy['website_data'] = dict(site_info_copy['website_data'])
            site_info_copy['website_data'].pop('response_body_base64', None)
            data_to_append = site_info_copy['website_data']
        else:
            data_to_append = site_info_copy

        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        file_path = os.path.join(output_dir, "undetect.json")
        tmp_path = file_path + ".tmp"

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

            data.append(data_to_append)

            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4)
                f.flush()
                os.fsync(f.fileno())

            os.replace(tmp_path, file_path)
