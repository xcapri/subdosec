from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from .entities import Fingerprint, ScanConfig, ScanResult

class FingerprintRepository(ABC):
    @abstractmethod
    def fetch_fingerprints(self, host_scan_prod: str, update: bool) -> Dict[str, List[Dict[str, Any]]]:
        """Fetch fingerprints from server or read from local cache."""
        pass

    @abstractmethod
    def read_local_fingerprints(self, file_path: str, host_scan_prod: str) -> Dict[str, List[Dict[str, Any]]]:
        """Read fingerprint list from local file and merge with cached fingerprints."""
        pass

    @abstractmethod
    def submit_fingerprint(self, file_path: str) -> bool:
        """Submit a local fingerprint file to the admin server."""
        pass


class ServerManager(ABC):
    @abstractmethod
    def ensure_server_running(self) -> None:
        """Ensure local Node.js scan server is running."""
        pass

    @abstractmethod
    def kill_server(self) -> None:
        """Kill the running Node.js scan server processes."""
        pass

    @abstractmethod
    def get_server_port(self) -> int:
        """Get the configured port of the Node.js server."""
        pass


class ScanClient(ABC):
    @abstractmethod
    def check_match(
        self,
        target: str,
        mode: str,
        title: str,
        status_code: int,
        body_match: bool,
        redirect_url: str,
        fingerprint_encoded: str,
        apikey: str,
        host_scan: str
    ) -> Dict[str, Any]:
        """Query the local scan server to check if fingerprint rules match."""
        pass

    @abstractmethod
    async def notify_vuln(
        self,
        web_data: Dict[str, Any],
        fingerprint_id: int,
        apikey: str,
        host_scan_prod: str,
        mode: str
    ) -> Dict[str, Any]:
        """Notify production server of a vulnerability detection."""
        pass

    @abstractmethod
    async def notify_undetect(
        self,
        site_info: Dict[str, Any],
        apikey: str,
        host_scan_prod: str,
        mode: str
    ) -> Dict[str, Any]:
        """Notify production server of an undetected site."""
        pass


class LocalStorage(ABC):
    @abstractmethod
    def get_user_dir(self) -> str:
        """Get the directory where subdosec data and configuration is stored."""
        pass

    @abstractmethod
    def load_env_vars(self, mode: str) -> tuple:
        """Load environment variables, setting defaults if file is missing."""
        pass

    @abstractmethod
    def init_key(self, apikey: str) -> None:
        """Write client APIKEY into the env storage."""
        pass

    @abstractmethod
    async def save_vuln_local(
        self,
        web_data: Dict[str, Any],
        service: str,
        fingerprint_id: int,
        output_dir: str
    ) -> None:
        """Save vulnerable scan results to a local file."""
        pass

    @abstractmethod
    async def save_undetect_local(
        self,
        site_info: Dict[str, Any],
        output_dir: str
    ) -> None:
        """Save undetected scan results to a local file."""
        pass


class AIAnalyzer(ABC):
    @abstractmethod
    def analyze(self, data_file: str, fingerprint_services: List[str]) -> list:
        """Analyze undetected domains using Gemini API."""
        pass
