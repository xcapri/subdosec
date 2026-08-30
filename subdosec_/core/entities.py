from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

@dataclass
class Fingerprint:
    fid: int
    service: str
    name: str
    status_fingerprint: int  # 1 = False Positive, others = Active
    rules: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanConfig:
    mode: str = "public"
    vuln_only: bool = False
    print_errors: bool = False
    thread_count: int = 10
    verbose: bool = False
    local_mode: bool = False
    output_dir: Optional[str] = None
    local_undetect_dir: Optional[str] = None
    skip_undetect_server: bool = False
    private_fingerprint_path: Optional[str] = None
    resume: bool = False
    
@dataclass
class ScanResult:
    target: str
    is_matched: bool
    service: Optional[str] = None
    website_data: Optional[Dict[str, Any]] = None
    fingerprint_id: Optional[int] = None
