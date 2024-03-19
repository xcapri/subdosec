import sys
import os
import requests
from dotenv import load_dotenv

def scan_by_web():
    # Read targets from stdin
    lines = sys.stdin.readlines()
    
    # Remove newline characters from the end of each line
    lines = [line.strip() for line in lines]

    # Determine the mode (public or private)
    mode = os.getenv('MODE')
        
    # Get the API key based on the mode
    apikey = os.getenv('APIKEY') if mode == 'private' else os.getenv('PUBLIC_API_KEY')
    outputscan = os.getenv('OUTPUT_SCAN_PRIV') if mode == 'private' else os.getenv('OUTPUT_SCAN_PUB')
    

    host = os.getenv('SCAN_API_HOST')

    # Create promises for each target
    results = []
    for target in lines:
        response = requests.post(host, headers={'Subdosec-Apikey': apikey}, json={'target': target, 'mode': mode})
        data = response.json()
        results.append(data)

        
        # Check if success is True for this target
        if data.get('isMatched') != False:
            print(f"Found subdomain takeover with service {data['isMatched']}: {outputscan}{data['isMatched']}")
        else:
            print(f"{target} Not vulnerable")

    return results

# Execute the function
if __name__ == "__main__":
    load_dotenv()
    scan_by_web()
