#!/usr/bin/python3

import sys
import os
import re
import json
import base64
import argparse
import requests
from dotenv import load_dotenv, set_key
from bs4 import BeautifulSoup
import urllib3
import aiohttp
import asyncio
import pyfiglet
import subprocess
import platform
from requests.exceptions import SSLError
import socket
import random
import time
import itertools
import psutil
from urllib.parse import urlparse
from google import genai
from google.genai import types
from contextlib import contextmanager
import threading
import concurrent.futures
import shutil

print_lock = threading.Lock()
file_lock = threading.Lock()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@contextmanager
def suppress_stderr():
    """Suppress stderr output at both Python and C/C++ library levels."""
    stderr_fd = sys.stderr.fileno()
    # Save a copy of the original stderr file descriptor
    with os.fdopen(os.dup(stderr_fd), 'wb') as old_stderr:
        # Redirect stderr to /dev/null
        with open(os.devnull, 'wb') as devnull:
            os.dup2(devnull.fileno(), stderr_fd)
        try:
            yield
        finally:
            # Restore stderr
            os.dup2(old_stderr.fileno(), stderr_fd)

# --------------------- LOADING SPINNER -----------------------

class Spinner:
    def __init__(self, message="Processing..."):
        self.spinner = itertools.cycle(['|', '/', '-', '\\'])
        self.stop_running = False
        self.message = message

    def start(self):
        def run():
            while not self.stop_running:
                sys.stdout.write(f"\r{self.message} {next(self.spinner)}")
                sys.stdout.flush()
                time.sleep(0.1)
            sys.stdout.write("\r" + " " * (len(self.message) + 2) + "\r")
            sys.stdout.flush()

        self.thread = threading.Thread(target=run)
        self.thread.start()

    def stop(self):
        self.stop_running = True
        self.thread.join()

def is_port_in_use(port):
    """Check if the given port is currently in use on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def get_random_unused_port():
    """Find a random unused port."""
    while True:
        port = random.randint(1024, 65535)
        if not is_port_in_use(port):
            return port

def kill_server():
    _, _, _, _, node_port = load_env_vars('public')
    node_port = int(node_port)

    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == node_port:
            try:
                proc = psutil.Process(conn.pid)
                print(f"[+] Killing process {conn.pid} on port {node_port} ({proc.name()})")
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"[-] Could not kill process {conn.pid}: {e}")

def get_node_env_dir():
    """Get the directory for the dedicated Node.js environment."""
    return os.path.join(os.path.expanduser("~"), ".subdosec", "node_vm")

def install_node_runtime():
    """Install Node.js v18.20.4 to the dedicated directory at runtime."""
    env_dir = get_node_env_dir()
    print(f"[Info] Installing dedicated Node.js v18.20.4 to {env_dir}...")
    try:
        import nodeenv
    except ImportError:
         print("[Info] Installing nodeenv...")
         subprocess.check_call([sys.executable, "-m", "pip", "install", "nodeenv"])
    
    os.makedirs(os.path.dirname(env_dir), exist_ok=True)
    subprocess.check_call([sys.executable, "-m", "nodeenv", "--node=18.20.4", "--prebuilt", "-v", "--force", env_dir])
    print("[Info] Node.js installed successfully.")

def get_node_paths():
    """Find Node.js and npm executables, prioritizing the dedicated environment."""
    
    # 1. Check dedicated ~/.subdosec/node_vm
    env_dir = get_node_env_dir()
    if platform.system() == 'Windows':
        custom_node = os.path.join(env_dir, 'Scripts', 'node.exe')
        custom_npm = os.path.join(env_dir, 'Scripts', 'npm.cmd')
        
        venv_node = os.path.join(sys.prefix, 'Scripts', 'node.exe')
        venv_npm = os.path.join(sys.prefix, 'Scripts', 'npm.cmd')
    else:
        custom_node = os.path.join(env_dir, 'bin', 'node')
        custom_npm = os.path.join(env_dir, 'bin', 'npm')
        
        venv_node = os.path.join(sys.prefix, 'bin', 'node')
        venv_npm = os.path.join(sys.prefix, 'bin', 'npm')

    # Selection Priority: Custom > Venv > System
    if os.path.exists(custom_node):
        return custom_node, custom_npm
        
    if os.path.exists(venv_node) and 'node' in venv_node.lower(): 
         # Basic check to ensure sys.prefix isn't just system root if not running in venv
         # Actually sys.prefix in pipx is reliable.
         return venv_node, venv_npm

    # System Fallback
    node_exe = shutil.which('node')
    npm_exe = shutil.which('npm')
    
    # Windows npm fallback
    if platform.system() == 'Windows' and npm_exe and not npm_exe.endswith('.cmd') and not npm_exe.endswith('.exe'):
         npm_exe = shutil.which('npm.cmd') or npm_exe

    return node_exe, npm_exe

def run_node_server():
    """Start the Node.js server with auto-healing capabilities."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    env_file = os.path.join(script_dir, 'config/.env')
    
    # Paths
    node_dir = os.path.join(script_dir, 'node')
    js_loc = os.path.join(node_dir, 'scan.js') 
    node_modules_dir = os.path.join(node_dir, 'node_modules')

    # 1. Load Configuration
    _, _, _, host_scan_prod, node_port = load_env_vars('public')
    fetch_fingerprints(host_scan_prod, False)

    # 2. Ensure Node.js Environment
    node_exe, npm_exe = get_node_paths()
    
    if not node_exe:
         print("[Warning] Node.js executable not found. Attempting auto-install...")
         try:
             install_node_runtime()
             node_exe, npm_exe = get_node_paths()
         except Exception as e:
             print(f"[Error] Failed to install Node.js automatically: {e}")
             sys.exit(1)

    if not node_exe:
         print("[Error] Node.js executable missing. Please install Node.js manually.")
         sys.exit(1)
         
    npm_exe = npm_exe or 'npm'

    # 3. Ensure Node Modules
    if os.path.exists(node_dir):
        os.chdir(node_dir)
    else:
        print(f"[Error] Node directory not found: {node_dir}")
        sys.exit(1)

    if not os.path.exists(node_modules_dir):
        print(f"[Info] Installing Node.js modules using {npm_exe}...")
        try:
            # Add node executable path to PATH enviroment variable for npm
            env = os.environ.copy()
            node_bin_dir = os.path.dirname(node_exe)
            env["PATH"] = f"{node_bin_dir}{os.pathsep}{env.get('PATH', '')}"

            # Capture output to display only on error
            subprocess.run([npm_exe, 'i'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True, env=env)
            print("[Info] Node.js modules installed.")
        except subprocess.CalledProcessError as e:
            print(f"[Error] Failed to install Node.js modules.")
            print(f"Details:\n{e.stderr}\n{e.stdout}")
            sys.exit(1)

    # 4. Port Management (Check & Rotate if needed)
    if is_port_in_use(int(node_port)):
        print(f"[Info] Port {node_port} is busy. Finding available port...")
        random_port = get_random_unused_port()
        set_key(env_file, 'PORT', str(random_port))
        print(f"[Info] Switched configuration to port: {random_port}")
        # Reload env to pick up the new port for this session
        os.environ["PORT"] = str(random_port) 
        node_port = str(random_port)

    # 5. Start Server
    print(f"[Info] Starting Node.js server using {node_exe} on port {node_port}...")
    env = os.environ.copy()
    env["PORT"] = node_port
    
    try:
        process = subprocess.Popen([node_exe, js_loc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        
        # 6. Verify Startup
        for _ in range(30):
            # Check if process crashed immediately
            if process.poll() is not None:
                print(f"[Error] Node.js server process exited unexpectedly with code {process.returncode}.")
                sys.exit(1)

            # Check if port is listening (success)
            if is_port_in_use(int(node_port)):
                print(f"[Success] Node.js server running in background (PID: {process.pid}).")
                sys.exit(0)
                
            time.sleep(1)

        print("[Error] Node.js server timed out waiting for port bind.")
        if process.poll() is None:
            process.terminate()
        sys.exit(1)

    except Exception as e:
        print(f"[Error] Failed to start Node.js server: {e}")
        sys.exit(1)


def init_key(apikey):
    """Initialize the API key in the .env file."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    env_file = os.path.join(script_dir, 'config/.env')
    
    load_dotenv(dotenv_path=env_file)
    set_key(env_file, 'APIKEY', apikey)
    print(f"API key has been written to {env_file}")

def load_env_vars(mode):
    """Load environment variables based on the mode."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    env_file = os.path.join(script_dir, 'config/.env')

    load_dotenv(dotenv_path=env_file)

    apikey = os.getenv('APIKEY') if mode == 'private' else os.getenv('PUBLIC_API_KEY')
    output_scan = os.getenv('OUTPUT_SCAN_PRIV') if mode == 'private' else os.getenv('OUTPUT_SCAN_PUB')
    host_scan = os.getenv('SCAN_API_HOST').replace('3000', os.getenv('PORT'))
    host_scan_prod = os.getenv('PROD_SCAN_API_HOST')
    node_port = os.getenv('PORT') 

    if not all([host_scan, output_scan]):
        raise ValueError("Missing required environment variables.")
    
    if mode == 'private' and not apikey:
        signup_url = os.getenv('SIGNUP_URL')
        raise ValueError(f"Create a password & apikey first at {signup_url}.\nThen run `subdosec -initkey your-key`")
    

    
    return apikey, output_scan, host_scan, host_scan_prod, node_port

def fetch_fingerprints(host_scan_prod, update):
    """Fetch fingerprints from API or load from cache if available (unless update is True)."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    offline_fingerprint = os.path.join(script_dir, 'config/offinger.json')

    if update or not os.path.exists(offline_fingerprint):
        url = host_scan_prod.replace('/api/scan/cli', '/api/getfinger')
        response = requests.get(url, timeout=30)
        response.raise_for_status()

        data = response.json()

        os.makedirs(os.path.dirname(offline_fingerprint), exist_ok=True)
        with open(offline_fingerprint, 'w') as f:
            json.dump(data, f, indent=2)

        if update:
            print("Update successful")
            return

        return data

    with open(offline_fingerprint, 'r') as f:
        return json.load(f)

def extract_title(content):
    """Extract the title from the HTML content."""
    soup = BeautifulSoup(content, 'html.parser')
    return soup.title.string if soup.title else 'No title found'

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
           return await response.json()

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

def autos_protocol(target):
    try:

        response = requests.get(target, verify=False, allow_redirects=True, timeout=30)
        if len(response.history) > 2:
            raise Exception(f"Too many redirects for {target}, skipping...")
        return response

    except SSLError as e:
        if '[SSL: TLSV1_ALERT_INTERNAL_ERROR]' in str(e):
            
            http_target = target.replace("https://", "http://")
            try:
                response = requests.get(http_target, verify=False, allow_redirects=False, timeout=30)
                return response

            except Exception as e:
                print(f"[Error] HTTP request failed: {e}")
                return None
        else:
            raise e

def analyze_target(target, mode, apikey, output_scan, host_scan, host_scan_prod, fingerprints, vuln_only, pe, o, su, lu, current_num=None, total_targets=None, verbose=False):
    """Analyze a single target and print the results."""
    try:
        target = target if target.startswith(('http://', 'https://')) else 'https://' + target

        response = autos_protocol(target)
        title = extract_title(response.text)

        status_code = response.history[0].status_code if response.history else response.status_code
        redirect_url = response.url if response.history else 'No redirects'
        clean_redirect_url = urlparse(redirect_url)._replace(query="").geturl()
        count_finger = len(fingerprints['fingerprints'])

        match_response = []
        for index, fingerprint in enumerate(fingerprints['fingerprints'], start=1):
            in_body_match = fingerprint['rules'].get('in_body', 'subdosec') in response.text
            fingerprint_encoded = base64.b64encode(json.dumps(fingerprint).encode('utf-8')).decode('utf-8')
            
            # Removed per-fingerprint progress display to avoid messy output with threading


            scan_payload = {
                'target': target,
                'mode': mode,
                'title_fu': title,
                'sc_fu': status_code,
                'body_fu': in_body_match,
                'redirect_url': clean_redirect_url,
                'fingerprint_new': fingerprint_encoded,
            }
            scan_response = requests.post(host_scan, headers={'Subdosec-Apikey': apikey}, json=scan_payload)
            match_response.append(scan_response.json())

        if any(item.get('isMatched') for item in match_response):
     
            service = next(item.get('service').get('service') for item in match_response if item.get('isMatched'))
            web_data = next(item.get('website_data') for item in match_response if item.get('isMatched'))
            fingerprint_id = next(item.get('service').get('fid') for item in match_response if item.get('isMatched'))
            
            prefix = ""
            if verbose and current_num is not None and total_targets is not None:
                prefix = f"[{current_num}/{total_targets}] "

            msg = f"{prefix}{target} [{service}] [VULN] [SAVED]" if o else f"{prefix}{target} [VULN] {output_scan}{service}"
            with print_lock:
                print(msg)

            if o:
                asyncio.run(save_local(web_data, service, fingerprint_id, o))
            else:
                asyncio.run(vuln_site(web_data, fingerprint_id, apikey, host_scan_prod, mode))


        elif not vuln_only:
            prefix = ""
            if verbose and current_num is not None and total_targets is not None:
                prefix = f"[{current_num}/{total_targets}] "

            with print_lock:
                print(f"{prefix}{target} [UNDETECT]")
            if lu:
                asyncio.run(undetect_site_localy(match_response[0], lu))
            elif not su:
                asyncio.run(undetect_site(match_response[0], apikey, host_scan_prod, mode))


    except Exception as e:
        if pe:
            with print_lock:
                print(f"[Error] {target} : {e}")

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

def analyze_with_gemini(data_file):
    try:
        # Load original undetect.json
        with open(data_file, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)

        # Load fingerprints
        fingerprints = check_fingerprint(0)
        fingerprint_services = [fp['service'] for fp in fingerprints]

        # Clean data: remove entries whose CNAME matches any fingerprint service
        cleaned_data = []
        skipped_count = 0

        for entry in raw_data:
            cnamelist = entry.get('cname_records') or []
            is_fp = False
            for cname in cnamelist:
                if any(cname.endswith(fp_service) for fp_service in fingerprint_services):
                    is_fp = True
                    break
            if not is_fp:
                cleaned_data.append(entry)
            else:
                skipped_count += 1

        print(f"[INFO] PURE UNDETECTED {skipped_count} | Subdomains are not detected as vulnerable even though they have passed the subdosec scan..\n")

        if not cleaned_data:
            print("[INFO] No new potential subdomains to analyze.\n")
            return

        # Ensure all entries have lists for cname and a_records
        for entry in cleaned_data:
            entry['cname_records'] = entry.get('cname_records') or []
            entry['a_records'] = entry.get('a_records') or []

        script_dir = os.path.dirname(os.path.abspath(__file__))
        env_file = os.path.join(script_dir, 'config/.env')
        load_dotenv(dotenv_path=env_file)

        my_api_key = os.getenv('GEMINI_API_KEY')

        # Check if API key is set
        if not my_api_key or my_api_key.strip() == '':
            print("[!] Gemini API key not found!")
            print("[+] Please enter your Gemini API key.")
            print("[+] You can get your API key from: https://aistudio.google.com/app/apikey\n")

            # Prompt user for API key
            user_api_key = input("Enter your Gemini API key: ").strip()

            if not user_api_key:
                print("[Error] No API key provided. Exiting...")
                return

            # Save the API key to .env file
            set_key(env_file, 'GEMINI_API_KEY', user_api_key)
            print(f"[+] API key has been saved to {env_file}\n")
            my_api_key = user_api_key

        # Configure Gemini Client
        client = genai.Client(api_key=my_api_key)

        # Batch processing
        chunk_size = 5
        results = []
        total_items = len(cleaned_data)
        batches = [cleaned_data[i:i + chunk_size] for i in range(0, total_items, chunk_size)]
        total_batches = len(batches)

        if total_batches > 1:
            print(f"[INFO] Analyzing {total_items} items in {total_batches} batches.\n")
        else:
            print(f"[INFO] Analyzing {total_items} items with Gemini.\n")

        for i, batch in enumerate(batches, 1):
            prompt = f"""
        cat undetected.json
        {json.dumps(batch, indent=4)}

        Based on the CNAME record (clear the CNAME to the root domain as the service name) or A record, please find relevant documents/guides/articles on how to set up a custom domain, and read the guide on how to set up a custom domain on that service.

        Possible vulnerable and non-vulnerable rules:

        - If verification uses a CNAME based on user identity {{static not random}}.servicename.tld, it is vulnerable.
        - If verification uses a CNAME based on user identity {{based on user domain or company name ,or anything related to user}}.servicename.tld, it is vulnerable.
        - If verification uses a CNAME based on user identity {{static event provide from service}}.servicename.tld, it is vulnerable.
        - If verification uses a CNAME based on user identity {{user/company/rootdomain/static cname provider from service/load-balancer}}.servicename.tld but there is TXT record verification, it is not vulnerable.
        - If verification uses a random cname {{random}}.servicename.tld, it is not vulnerable.
        - If there is a verification keyword for ownership by TXT record or any dynamic record, it is not vulnerable.
        - If verification is performed without a TXT record and without a dynamic CNAME, the site is potentially vulnerable to subdomain hijacking attacks.
        - But conversely, if the user requires verification using a TXT record, it is not vulnerable.
        - If the cname/a record information I provided is in the can-t-takeover repository, please read that and identify whether it is vulnerable, not vulnerable, or vulnerable (edge case).
        * For txt records, there is no need to compare them with the data I sent. That is the result. So focus on the indications from the custom domain article you read.
        * The main rule is, if there is a TXT record keyword in the custom domain article, immediately consider it not vulnerable.
        * The data I send is only used to display custom domain articles related to that service.
        * Do not analyze and search for articles if the a/cname service information is contained in the fingerprint in the subdosec. (skip the process and output)
        * Please find & read using latest article or docs.

        Fingerprint subdosec
        {fingerprints}

        Then I want output from you only like this:
        * If there are multiple domains on the same service in the data I sent, the output should only be one.

        if multiple
        ```
        [
        {{
            "CNAME": "<cname-if-exists>",
            "A_RECORD": "<a-record-if-exists>",
            "DOMAIN": "<subdomain-provided>",
            "TAKEOVER": "POSSIBLE",
            "REASON": "simple reason",
            "LINK_REFERENCE": "<docs-or-article-link>"
        }},
        {{
            "CNAME": "<cname-if-exists>",
            "A_RECORD": "<a-record-if-exists>",
            "DOMAIN": "<subdomain-provided>",
            "TAKEOVER": "NOT",
            "REASON": "simple reason",
            "LINK_REFERENCE": "<docs-or-article-link>"
        }}
        ]
        ```
        """
            
            # Start loading spinner
            spinner_msg = f"Analyzing batch {i}/{total_batches}" if total_batches > 1 else "Analyzing with Gemini"
            spinner = Spinner(spinner_msg)
            spinner.start()

            try:
                # Run Gemini with STDERR suppressed
                with suppress_stderr():
                    response = client.models.generate_content(
                        model='gemini-2.5-flash',
                        contents=prompt,
                        config=types.GenerateContentConfig(
                            safety_settings=[
                                types.SafetySetting(
                                    category=types.HarmCategory.HARM_CATEGORY_HATE_SPEECH,
                                    threshold=types.HarmBlockThreshold.BLOCK_NONE,
                                ),
                                types.SafetySetting(
                                    category=types.HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
                                    threshold=types.HarmBlockThreshold.BLOCK_NONE,
                                ),
                                types.SafetySetting(
                                    category=types.HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
                                    threshold=types.HarmBlockThreshold.BLOCK_NONE,
                                ),
                                types.SafetySetting(
                                    category=types.HarmCategory.HARM_CATEGORY_HARASSMENT,
                                    threshold=types.HarmBlockThreshold.BLOCK_NONE,
                                ),
                            ]
                        )
                    )
                spinner.stop()

                # Extract and append JSON result
                match = re.search(r"```json\s*(\[\s*{.*?}\s*\])\s*```", response.text, re.DOTALL)
                if match:
                    cleaned_json = match.group(1)
                    batch_results = json.loads(cleaned_json)
                    results.extend(batch_results)
                else: 
                     # Fallback if markdown code block is missing but json is present
                     try:
                        batch_results = json.loads(response.text)
                        if isinstance(batch_results, list):
                           results.extend(batch_results)
                     except:
                        pass 

            except Exception as e:
                spinner.stop()
                print(f"[Warning] Batch {i} failed: {e}")

            # Print progress after each batch only if multiple batches
            if total_batches > 1:
                print(f"[INFO] Progress: {min(i * chunk_size, total_items)}/{total_items} data analyzed.")


        # Finally, print all results
        print("\nNEW POTENTIAL :\n")
        if results:
            for entry in results:
                cname = entry.get('CNAME', '-')
                a_record = entry.get('A_RECORD') or []
                if not isinstance(a_record, list):
                    a_record = [a_record]

                print(f"Domain     : {entry.get('DOMAIN', '-')}")
                print(f"  CNAME    : {cname}")
                print(f"  A Record : {', '.join(a_record)}")
                print(f"  Takeover : {entry.get('TAKEOVER', '-')}")
                print(f"  Reason   : {entry.get('REASON', '-')}")
                print(f"  Reference: {entry.get('LINK_REFERENCE', '-')}")
                print("=" * 80)
        else:
            print("No results found.")

    except FileNotFoundError:
        print(f"[Error] File not found: {data_file}")
    except json.JSONDecodeError:
        print(f"[Error] Invalid JSON format in file: {data_file}")
    except Exception as e:
        print(f"[Error] An unexpected error occurred: {e}")


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
    
def scan_by_web(mode, vuln_only, pe, lf, o, pf, su, lu, verbose, threads=10):
    """Main function to perform the web scanning."""
    try:
        if mode == 'public' and not (o or su or lu):
            print(f"[WARNING] You are not using private mode; results will be public.")

        apikey, output_scan, host_scan, host_scan_prod, _ = load_env_vars(mode)
        fingerprints = fetch_fingerprints(host_scan_prod, False)
        filtered_fingerprints = {'fingerprints': [fingerprint for fingerprint in fingerprints['fingerprints'] if fingerprint['status_fingerprint'] != 1]} 
        lf_list = [x.strip() for x in lf.split(',')]
        
        lock_filtered_fingerprints = {
            "fingerprints": [
                fingerprint for fingerprint in fingerprints['fingerprints']
                if fingerprint['service'] in lf_list
            ]
        }

        final_finger = read_local_finger(pf, host_scan_prod) if pf else (lock_filtered_fingerprints if lf != 'all' else filtered_fingerprints)

        targets = [line.strip() for line in sys.stdin if line.strip()]
        total_targets = len(targets)

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for i, target in enumerate(targets, 1):
                futures.append(executor.submit(
                    analyze_target, target, mode, apikey, output_scan, host_scan, host_scan_prod,
                    final_finger, vuln_only, pe, o, su, lu, current_num=i, total_targets=total_targets,
                    verbose=verbose
                ))
            
            # Wait for all futures to complete (optional, context manager handles it too)
            concurrent.futures.wait(futures)

    except ValueError as e:
        print(f"[Configuration Error] {e}")


def main():
    """Entry point for the script."""
    
    print(f"{pyfiglet.figlet_format('Subdosec', font='slant')}\n")
    parser = argparse.ArgumentParser(description='Subdomain takeover scanner.')
    parser.add_argument('-mode', choices=['private', 'public'], default='public', help='Mode of operation (private/public)')
    parser.add_argument('-initkey', help='Initialize the API key')
    parser.add_argument('-vo', action='store_true', help='VULN Only: Hide UNDETECT messages')
    parser.add_argument('-pe', action='store_true', help='Print Error: When there are problems detecting your target')
    parser.add_argument('-ins', action='store_true', help='Prepar node & start server')
    parser.add_argument('-pf', type=str,  help='Private Fingerprint: uses your local fingerprint. Example: -pf /path/to/tko.json')
    parser.add_argument('-lf', default='all',  help='Fingerprint lock: to focus on one or multiple fingerprints. (-lf github.io,surge.sh) and leave this arg to scan all fingerprints')
    parser.add_argument('-sfid', action='store_true',  help='To view all available fingerprint ids.')
    parser.add_argument('-ks', action='store_true',  help='To shut down the server node if you want to not use subdosec for a long time.')
    parser.add_argument('-o', type=str, help='Save result locally to the specified path. Example: -o /path/to/dir')
    parser.add_argument('-su', action='store_true', help='Skip undetect will not stored to server (https://subdosec.vulnshot.com/result/undetected)')
    parser.add_argument('-lu', type=str, help='Undetec stored localy to the specified path. Example: -lu /path/to/dir')
    parser.add_argument('-uf', action='store_true', help='Update Fingerprint')
    parser.add_argument('-unai', type=str, help='Analyze undetected subdomains using AI. Example: -unai /path/to/undetect.json')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show progress count (e.g. [1/10])')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads to use for scanning (default: 10)')

    
    args = parser.parse_args()

    if args.initkey:
        init_key(args.initkey)
    elif args.uf:
        _, _, _, host_scan_prod, _ = load_env_vars('public')
        fetch_fingerprints(host_scan_prod, True)
    elif args.ins:
        run_node_server()
    elif args.pf and not args.o:
        print("Error: If you use -pf, you must save the scan to local with -o /path/to/save")
        sys.exit(1)
    elif args.sfid:
        check_fingerprint(1)
    elif args.ks:
        kill_server()
    elif args.unai:
        analyze_with_gemini(args.unai)
    else:
        scan_by_web(args.mode, args.vo, args.pe, args.lf,  args.o,  args.pf, args.su, args.lu, args.verbose, args.threads)

if __name__ == "__main__":
    main()