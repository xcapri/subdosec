from typing import List
from ..ports import FingerprintRepository
from ...shared import colors


class FingerprintUseCase:
    def __init__(self, fp_repo: FingerprintRepository):
        self.fp_repo = fp_repo

    def list_fingerprints(self, host_scan_prod: str) -> None:
        """List cached fingerprints."""
        try:
            fingerprints_data = self.fp_repo.fetch_fingerprints(host_scan_prod, False)
            for fingerprint in fingerprints_data.get('fingerprints', []):
                service = fingerprint.get('service', '')
                name = fingerprint.get('name', '')
                status = "[False Positive]" if fingerprint.get('status_fingerprint') == 1 else "[Active]"
                print(colors.fingerprint_line(service, name, status))
        except Exception as e:
            print(colors.error(str(e)))

    def update_fingerprints(self, host_scan_prod: str) -> None:
        """Force update fingerprints from the remote production server."""
        try:
            self.fp_repo.fetch_fingerprints(host_scan_prod, True)
        except Exception as e:
            print(colors.error(str(e)))

    def submit_fingerprint(self, file_path: str) -> None:
        """Submit local fingerprint definition to server."""
        try:
            self.fp_repo.submit_fingerprint(file_path)
        except Exception as e:
            print(colors.error(str(e)))
