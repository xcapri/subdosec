import os
import json
import re
import sys 
from dotenv import set_key, load_dotenv
from google import genai
from google.genai import types

from .app_config import get_user_dir, load_env_vars
from .utils import Spinner, suppress_stderr
from .api import check_fingerprint

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

        # Use user directory for config
        user_dir = get_user_dir()
        env_file = os.path.join(user_dir, '.env')
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


        # Your role
        Put yourself in the shoes of a bug hunter or security researcher who is searching for articles on “service-name custom domain” or “service-name subdomain takeover.” Then read the articles you find and draw conclusions based on the rules I have provided.

        # Main Rules
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
        * Please find & read using latest article or docs.


        # Output rules
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
