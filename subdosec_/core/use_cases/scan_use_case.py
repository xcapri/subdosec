import sys
import os
import asyncio
import concurrent.futures
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

from ..entities import ScanConfig, Fingerprint
from ..ports import FingerprintRepository, ServerManager, ScanClient, LocalStorage
from ..progress import ProgressTracker
from ...shared import colors
from ...shared.utils import print_lock, extract_title, autos_protocol


class ScanUseCase:
    def __init__(
        self,
        fp_repo: FingerprintRepository,
        server_mgr: ServerManager,
        scan_client: ScanClient,
        storage: LocalStorage
    ):
        self.fp_repo = fp_repo
        self.server_mgr = server_mgr
        self.scan_client = scan_client
        self.storage = storage

    def execute(self, config: ScanConfig, targets: List[str]) -> None:
        try:
            # Auto-start server if not running
            self.server_mgr.ensure_server_running()

            if config.mode == 'public' and not (config.output_dir or config.skip_undetect_server or config.local_undetect_dir):
                print(colors.warning("You are not using private mode; results will be public."))

            apikey, output_scan, host_scan, host_scan_prod, _ = self.storage.load_env_vars(config.mode)
            
            fingerprints_data = self.fp_repo.fetch_fingerprints(host_scan_prod, False)
            fingerprints_list = fingerprints_data.get('fingerprints', [])

            # Filter out status_fingerprint == 1 (False Positives)
            filtered_fingerprints = {
                'fingerprints': [fp for fp in fingerprints_list if fp.get('status_fingerprint') != 1]
            }

            # Apply lock fingerprints if specified
            if config.private_fingerprint_path:
                final_finger = self.fp_repo.read_local_fingerprints(config.private_fingerprint_path, host_scan_prod)
            elif config.mode == 'public' or config.mode == 'private':
                # Lock target service filter
                # E.g. -lf github.io,surge.sh
                if hasattr(config, 'lock_fingerprints') and config.lock_fingerprints and config.lock_fingerprints != 'all':
                    lf_list = [x.strip() for x in config.lock_fingerprints.split(',')]
                    lock_filtered = {
                        "fingerprints": [fp for fp in fingerprints_list if fp.get('service') in lf_list]
                    }
                    final_finger = lock_filtered
                else:
                    final_finger = filtered_fingerprints
            else:
                final_finger = filtered_fingerprints

            # ── Progress / Resume ────────────────────────────────────
            progress_dir = os.path.join(self.storage.get_user_dir(), "progress")
            tracker = ProgressTracker(progress_dir)

            if config.resume and tracker.has_pending_session():
                remaining = tracker.load_remaining_targets()
                if remaining is None:
                    print(colors.error("Failed to read previous session. Starting fresh scan."))
                    tracker.discard_session()
                elif len(remaining) == 0:
                    print(colors.info("Previous session already completed. Nothing to resume."))
                    tracker.finish_session()
                    return
                else:
                    session_cfg = tracker.load_session_config()
                    total_original = (session_cfg or {}).get("_total_original", len(remaining))
                    skipped = total_original - len(remaining)

                    targets = remaining
                    print(colors.info(f"Resuming session — {skipped} already done, {len(targets)} remaining."))
                    tracker.resume_session()
            elif config.resume and not tracker.has_pending_session():
                print(colors.warning("No interrupted session found. Nothing to resume."))
                return
            else:
                # Discard stale session (if any) and start fresh
                if tracker.has_pending_session():
                    tracker.discard_session()

                if not targets:
                    return

                config_snapshot = {
                    "mode": config.mode,
                    "output_dir": config.output_dir,
                    "local_undetect_dir": config.local_undetect_dir,
                    "_total_original": len(targets),
                }
                tracker.start_session(targets, config_snapshot)

            # ── Scan ─────────────────────────────────────────────────
            total_targets = len(targets)

            with concurrent.futures.ThreadPoolExecutor(max_workers=config.thread_count) as executor:
                futures = []
                for i, target in enumerate(targets, 1):
                    futures.append(executor.submit(
                        self._analyze_target,
                        target=target,
                        config=config,
                        apikey=apikey,
                        output_scan=output_scan,
                        host_scan=host_scan,
                        host_scan_prod=host_scan_prod,
                        fingerprints=final_finger,
                        current_num=i,
                        total_targets=total_targets,
                        tracker=tracker
                    ))
                
                concurrent.futures.wait(futures)

            # ── Cleanup ──────────────────────────────────────────────
            tracker.finish_session()

            print("\n")
            if config.output_dir:
                print(colors.path_label("VULN DIRECTORY ", os.path.abspath(config.output_dir)))
            if config.local_undetect_dir:
                print(colors.path_label("UNDETECT FILE  ", os.path.abspath(os.path.join(config.local_undetect_dir, 'undetect.json'))))

        except ValueError as e:
            print(colors.error(f"Configuration: {e}"))

    def _analyze_target(
        self,
        target: str,
        config: ScanConfig,
        apikey: str,
        output_scan: str,
        host_scan: str,
        host_scan_prod: str,
        fingerprints: Dict[str, Any],
        current_num: int,
        total_targets: int,
        tracker: ProgressTracker
    ) -> None:
        try:
            orig_target = target
            target = target if target.startswith(('http://', 'https://')) else 'https://' + target

            response = autos_protocol(target)
            if response is None:
                tracker.mark_done(orig_target)
                return

            title = extract_title(response.text)

            status_code = response.history[0].status_code if response.history else response.status_code
            redirect_url = response.url if response.history else 'No redirects'
            clean_redirect_url = urlparse(redirect_url)._replace(query="").geturl()

            import base64
            import json

            match_response = []
            for fingerprint in fingerprints.get('fingerprints', []):
                in_body_match = fingerprint.get('rules', {}).get('in_body', 'subdosec') in response.text
                fingerprint_encoded = base64.b64encode(json.dumps(fingerprint).encode('utf-8')).decode('utf-8')

                scan_res = self.scan_client.check_match(
                    target=target,
                    mode=config.mode,
                    title=title,
                    status_code=status_code,
                    body_match=in_body_match,
                    redirect_url=clean_redirect_url,
                    fingerprint_encoded=fingerprint_encoded,
                    apikey=apikey,
                    host_scan=host_scan
                )
                match_response.append(scan_res)

            if any(item.get('isMatched') for item in match_response):
                matched_item = next(item for item in match_response if item.get('isMatched'))
                service = matched_item.get('service', {}).get('service', '')
                web_data = matched_item.get('website_data', {})
                fingerprint_id = matched_item.get('service', {}).get('fid', 0)

                prefix = ""
                if config.verbose:
                    prefix = f"[{current_num}/{total_targets}] "

                msg = f"{prefix}{colors.domain(target)} {colors.service_tag(service)} {colors.vuln('')} {colors.saved()}" if config.output_dir else f"{prefix}{colors.domain(target)} {colors.vuln('')} {colors.link(output_scan + service)}"
                with print_lock:
                    print(msg)

                if config.output_dir:
                    asyncio.run(self.storage.save_vuln_local(web_data, service, fingerprint_id, config.output_dir))
                else:
                    asyncio.run(self.scan_client.notify_vuln(web_data, fingerprint_id, apikey, host_scan_prod, config.mode))

            elif not config.vuln_only:
                prefix = ""
                if config.verbose:
                    prefix = f"[{current_num}/{total_targets}] "

                with print_lock:
                    print(f"{prefix}{colors.domain(target)} {colors.undetect()}")

                if config.local_undetect_dir:
                    asyncio.run(self.storage.save_undetect_local(match_response[0], config.local_undetect_dir))
                elif not config.skip_undetect_server:
                    asyncio.run(self.scan_client.notify_undetect(match_response[0], apikey, host_scan_prod, config.mode))

            # Mark target as done after all processing is complete
            tracker.mark_done(orig_target)

        except Exception as e:
            # Still mark as done to avoid re-scanning broken targets forever
            tracker.mark_done(orig_target)
            if config.print_errors:
                with print_lock:
                    print(colors.error(f"{target} : {e}"))

