import sys
import os
import requests
from dotenv import load_dotenv

def scan_by_web():
    targets = [line.strip() for line in sys.stdin]
    mode = os.getenv('MODE')
    apikey = os.getenv('APIKEY') if mode == 'private' else os.getenv('PUBLIC_API_KEY')
    output_scan = os.getenv('OUTPUT_SCAN_PRIV') if mode == 'private' else os.getenv('OUTPUT_SCAN_PUB')
    host = os.getenv('SCAN_API_HOST')

    for target in targets:
        response = requests.post(host, headers={'Subdosec-Apikey': apikey}, json={'target': target, 'mode': mode})
        data = response.json()

        if data.get('isMatched') and data.get('success'):
            services = ", ".join(data['isMatched'])
            print(f"[VULN] {target} : {output_scan}{services}")
        else:
            print(f"{target} Not vulnerable")

if __name__ == "__main__":
    load_dotenv()
    scan_by_web()
