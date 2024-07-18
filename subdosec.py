import sys
import os
import requests
from requests.exceptions import RequestException, HTTPError, ConnectionError
from dotenv import load_dotenv
from bs4 import BeautifulSoup 
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def scan_by_web():
    # Read targets from stdin
    targets = [line.strip() for line in sys.stdin]
    
    # Load environment variables
    load_dotenv()

    # Determine mode and API key based on environment variables
    mode = os.getenv('MODE', 'public')
    apikey = os.getenv('PRIVATE_API_KEY') if mode == 'private' else os.getenv('PUBLIC_API_KEY')
    output_scan = os.getenv('OUTPUT_SCAN_PRIV') if mode == 'private' else os.getenv('OUTPUT_SCAN_PUB')
    host_scan = os.getenv('SCAN_API_HOST')

    # Ensure required environment variables are set
    if not all([host_scan, apikey, output_scan]):
        print("Missing required environment variables.")
        return
    
    for target in targets:
        try:
            # Make GET request to target URL with SSL verification disabled
            req = requests.get(target, verify=False)

            # Encode response body to hexadecimal
            web_body = req.text.encode('utf-8').hex()

            # Extract title using BeautifulSoup
            soup = BeautifulSoup(req.content, 'html.parser')
            title = soup.title.string if soup.title else 'No title found'

            # Get status code and redirect URL
            status_code = req.status_code
            redirect_url = req.url if req.history else 'No redirects'

            # Send POST request to host_scan endpoint
            response = requests.post(host_scan, headers={'Subdosec-Apikey': apikey}, json={
                'target': target,
                'mode': mode,
                'title_fu': title,
                'sc_fu': status_code,
                'body_fu': web_body,
                'redirect_url': redirect_url
            })

            data = response.json()

            # Check response data and print results
            if data.get('isMatched') and data.get('success'):
                services = ", ".join(data['isMatched'])
                print(f"[VULN] {target} : {output_scan}{services}")
            else:
                print(f"{target} Not vulnerable")

        except HTTPError as e:
            print(f"[HTTP Error] {target} : {e}")
        except ConnectionError as e:
            print(f"[Connection Error] {target} : {e}")
        except RequestException as e:
            print(f"[Request Error] {target} : {e}")
        except Exception as e:
            print(f"[Error] {target} : {e}")

if __name__ == "__main__":
    scan_by_web()