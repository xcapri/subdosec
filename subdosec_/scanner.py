import sys
import os
import base64
import json
import asyncio
import requests
import concurrent.futures
from urllib.parse import urlparse

from .app_config import print_lock, load_env_vars
from .utils import extract_title, autos_protocol
from .api import (
    fetch_fingerprints, 
    undetect_site, 
    undetect_site_localy, 
    vuln_site, 
    save_local, 
    read_local_finger
)

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
            
            # Wait for all futures to complete
            concurrent.futures.wait(futures)
        
        print("\n")
        if o:
            print(f"VULN DIRECTORY \t: {os.path.abspath(o)}")
        if lu:
            print(f"UNDETECT FILE \t: {os.path.abspath(os.path.join(lu, 'undetect.json'))}")

    except ValueError as e:
        print(f"[Configuration Error] {e}")
