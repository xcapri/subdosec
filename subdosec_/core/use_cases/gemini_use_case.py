import os
import json
from typing import List

from ..ports import AIAnalyzer, FingerprintRepository
from ...shared import colors


class GeminiUseCase:
    def __init__(self, fp_repo: FingerprintRepository, ai_analyzer: AIAnalyzer):
        self.fp_repo = fp_repo
        self.ai_analyzer = ai_analyzer

    def execute(self, data_file: str, host_scan_prod: str) -> None:
        try:
            # Load original undetect.json
            with open(data_file, 'r', encoding='utf-8') as f:
                raw_data = json.load(f)

            # Load fingerprints via repo
            fingerprints_data = self.fp_repo.fetch_fingerprints(host_scan_prod, False)
            fingerprint_services = [fp['service'] for fp in fingerprints_data.get('fingerprints', [])]

            # Clean data: remove entries whose CNAME matches any fingerprint service
            seen_subdomains = set()
            cleaned_data = []
            skipped_count = 0

            for entry in raw_data:
                subdomain = entry.get('subdomain')
                if subdomain:
                    if subdomain in seen_subdomains:
                        continue
                    seen_subdomains.add(subdomain)

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

            print(colors.info(f"PURE UNDETECTED {skipped_count} | Subdomains are not detected as vulnerable even though they have passed the subdosec scan.") + "\n")

            if not cleaned_data:
                print(colors.info("No new potential subdomains to analyze.") + "\n")
                return

            # Ensure all entries have lists for cname and a_records
            for entry in cleaned_data:
                entry['cname_records'] = entry.get('cname_records') or []
                entry['a_records'] = entry.get('a_records') or []

            # Save cleaned data to a temporary file, or pass it directly to the analyzer.
            # To keep clean separation, the AIAnalyzer can accept the list of cleaned data dicts, 
            # rather than forcing it to read from a file. This is much cleaner!
            results = self.ai_analyzer.analyze(cleaned_data)

            print(colors.ai_header("NEW POTENTIAL :"))
            if results:
                for entry in results:
                    print(colors.ai_result_block(entry))
            else:
                print(f"{colors.DIM}No results found.{colors.RESET}")

            # Prepare records to save
            save_results = []
            analyzed_domains = set()

            for r in results:
                domain = r.get("DOMAIN")
                if domain:
                    dom_lower = domain.strip().lower()
                    analyzed_domains.add(dom_lower)
                    save_results.append({
                        "subdomain": domain,
                        "potential": "New Potential" if r.get("TAKEOVER") == "POSSIBLE" else "NOT VULN",
                        "reason": r.get("REASON") or "",
                        "reference": r.get("LINK_REFERENCE") or ""
                    })

            # Add skipped entries (Pure Undetect & NOT VULN)
            for entry in raw_data:
                sub = entry.get("subdomain")
                if sub:
                    sub_lower = sub.strip().lower()
                    if sub_lower not in analyzed_domains:
                        # Check if it was skipped due to matching fingerprint
                        cnamelist = entry.get('cname_records') or []
                        is_fp = False
                        for cname in cnamelist:
                            if any(cname.endswith(fp_service) for fp_service in fingerprint_services):
                                is_fp = True
                                break
                        if is_fp:
                            save_results.append({
                                "subdomain": sub,
                                "potential": "NOT VULN",
                                "reason": "Pure Undetect: matches known service fingerprint but scanner found no active takeover vulnerability",
                                "reference": ""
                            })

            # Merge with existing ai_analysis.json
            ai_file = os.path.join(os.path.dirname(data_file), "ai_analysis.json")
            existing_data = {}
            if os.path.exists(ai_file):
                try:
                    with open(ai_file, "r", encoding="utf-8") as f:
                        for item in json.load(f):
                            if item.get("subdomain"):
                                existing_data[item["subdomain"].strip().lower()] = item
                except Exception:
                    pass

            for item in save_results:
                existing_data[item["subdomain"].strip().lower()] = item

            # Write updated JSON
            with open(ai_file, "w", encoding="utf-8") as f:
                json.dump(list(existing_data.values()), f, indent=2)

            print("\n" + colors.success(f"Analysis results saved to {ai_file}"))

        except FileNotFoundError:
            print(colors.error(f"File not found: {data_file}"))
        except json.JSONDecodeError:
            print(colors.error(f"Invalid JSON format in file: {data_file}"))
        except Exception as e:
            print(colors.error(f"An unexpected error occurred: {e}"))

