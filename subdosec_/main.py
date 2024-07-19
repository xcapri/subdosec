#!/usr/bin/python3

import sys
import os
import json
import base64
import argparse
import requests
from requests.exceptions import RequestException, HTTPError, ConnectionError
from dotenv import load_dotenv, set_key
from bs4 import BeautifulSoup
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def init_key(apikey):
    """Initialize the API key in the .env file."""
    load_dotenv()
    script_dir = os.path.dirname(os.path.abspath(__file__))

    env_file = os.path.join(script_dir, 'config/.env')  
    set_key(env_file, 'APIKEY', apikey)
        
    print(f"API key has been written to {env_file}")

def load_env_vars(mode):
    """Load environment variables and ensure required ones are present."""
    load_dotenv()

    apikey = os.getenv('APIKEY') if mode == 'private' else os.getenv('PUBLIC_API_KEY')
    output_scan = os.getenv('OUTPUT_SCAN_PRIV') if mode == 'private' else os.getenv('OUTPUT_SCAN_PUB')
    host_scan = os.getenv('SCAN_API_HOST')

    # Check for missing required environment variables
    if not all([host_scan, output_scan]):
        raise ValueError("Missing required environment variables.")

    # Specific check for private mode
    if mode == 'private' and not apikey:
        raise ValueError(f"Create a password & apikey first at here {os.getenv('SIGNUP_URL')}.\nThen run python subdosec.py -initkey your-key")
    if mode == 'public' : 
        print(f"[WARNING] You don't use private mode, the result will be public.")
    return apikey, output_scan, host_scan

def fetch_fingerprints(host_scan):
    """Fetch and return fingerprints from the host_scan endpoint."""
    url = host_scan.replace('/api/scan/cli', '/api/getfinger')
    response = requests.get(url)
    response.raise_for_status()
    return response.json()

def extract_title(content):
    """Extract and return the title from the given HTML content."""
    soup = BeautifulSoup(content, 'html.parser')
    return soup.title.string if soup.title else 'No title found'

def analyze_target(target, mode, apikey, output_scan, host_scan, fingerprints):
    """Analyze a single target and print the results."""
    try:
        # Make GET request to target URL with SSL verification disabled
        response = requests.get(target, verify=False)

        title = extract_title(response.content)
        status_code = response.status_code
        redirect_url = response.url if response.history else 'No redirects'

        vulns = "NOT VULN"
        services = ""

        for fingerprint in fingerprints['fingerprints']:
            in_body_match = 'in_body' in fingerprint['rules'] and fingerprint['rules'].get('in_body') in response.text
            fingerprint_encode = base64.b64encode(json.dumps(fingerprint).encode('utf-8')).decode('utf-8')

            # Send POST request to host_scan endpoint
            scan_response = requests.post(host_scan, headers={'Subdosec-Apikey': apikey}, json={
                'target': target,
                'mode': mode,
                'title_fu': title,
                'sc_fu': status_code,
                'body_fu': in_body_match,
                'redirect_url': redirect_url,
                'fingerprint_new': fingerprint_encode
            })

            response_data = scan_response.json()

            if response_data.get('isMatched'):
                vulns = "VULN"
                matched_services = response_data.get('isMatched')
                services = ', '.join(matched_services) if isinstance(matched_services, list) else str(matched_services)
                services = output_scan + services

        services = services or ""
        print(f"[{vulns}] {target} | {services}")

    except HTTPError as e:
        print(f"[HTTP Error] {target} : {e}")
    except ConnectionError as e:
        print(f"[Connection Error] {target} : {e}")
    except RequestException as e:
        print(f"[Request Error] {target} : {e}")
    except Exception as e:
        print(f"[Error] {target} : {e}")

def scan_by_web(mode):
    """Main function to perform the web scanning."""
    try:
        apikey, output_scan, host_scan = load_env_vars(mode)
        fingerprints = fetch_fingerprints(host_scan)
        targets = [line.strip() for line in sys.stdin]

        for target in targets:
            analyze_target(target, mode, apikey, output_scan, host_scan, fingerprints)

    except ValueError as e:
        print(f"[Configuration Error] {e}")

def main():
    """Entry point for the script."""
    parser = argparse.ArgumentParser(description='Web scanner.')
    parser.add_argument('-mode', choices=['private', 'public'], default='public', help='Mode of operation (private/public)')
    parser.add_argument('-initkey', help='Initialize the API key')
    
    args = parser.parse_args()

    if args.initkey:
        init_key(args.initkey)
    else:
        scan_by_web(args.mode)

if __name__ == "__main__":
    main()