"""
Data helpers — load vuln / undetect results from ~/.subdosec/.
"""

import os
import json
from typing import Dict, List, Any


def load_vulns(user_dir: str) -> Dict[str, List[str]]:
    """Read every *_tko.txt in vulns/ → { service: [subdomain, …] }."""
    vulns_dir = os.path.join(user_dir, "vulns")
    result: Dict[str, List[str]] = {}
    if not os.path.isdir(vulns_dir):
        return result
    for fname in os.listdir(vulns_dir):
        if fname.endswith("_tko.txt"):
            service = fname.replace("_tko.txt", "")
            fpath = os.path.join(vulns_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    subs = list(dict.fromkeys(
                        line.strip() for line in f if line.strip()
                    ))  # deduplicate, preserve order
                if subs:
                    result[service] = subs
            except Exception:
                pass
    return result


def load_undetect(user_dir: str) -> List[Dict[str, Any]]:
    """Read undetect/undetect.json → list[dict]."""
    fpath = os.path.join(user_dir, "undetect", "undetect.json")
    if not os.path.isfile(fpath):
        return []
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            seen: set = set()
            unique: List[Dict[str, Any]] = []
            for item in data:
                sub = item.get("subdomain", "")
                if sub and sub not in seen:
                    seen.add(sub)
                    unique.append(item)
            return unique
        return []
    except Exception:
        return []


def load_service_map(user_dir: str) -> Dict[str, Dict[str, str]]:
    """Read offinger.json → { service: { logo, reference, name } }."""
    fpath = os.path.join(user_dir, "offinger.json")
    if not os.path.isfile(fpath):
        return {}
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        fingerprints = data.get("fingerprints", [])
        service_map = {}
        for fp in fingerprints:
            srv = fp.get("service")
            logo = fp.get("logo_service")
            ref = fp.get("reference")
            name = fp.get("name")
            if srv and srv not in service_map:
                service_map[srv] = {
                    "logo": logo or "",
                    "reference": ref or "",
                    "name": name or srv
                }
        return service_map
    except Exception:
        return {}


def load_ai_analysis(user_dir: str) -> Dict[str, Dict[str, Any]]:
    """Read undetect/ai_analysis.json → { subdomain: { potential, reason, reference } }."""
    fpath = os.path.join(user_dir, "undetect", "ai_analysis.json")
    if not os.path.isfile(fpath):
        return {}
    try:
        with open(fpath, "r", encoding="utf-8") as f:
            data = json.load(f)
        result = {}
        for item in data:
            sub = item.get("subdomain")
            if sub:
                result[sub.strip().lower()] = {
                    "potential": item.get("potential") or "Unanalyz",
                    "reason": item.get("reason") or "",
                    "reference": item.get("reference") or ""
                }
        return result
    except Exception:
        return {}


def build_api_payload(user_dir: str) -> dict:
    """Build the full JSON response for /api/data."""
    vulns = load_vulns(user_dir)
    undetect = load_undetect(user_dir)
    service_map = load_service_map(user_dir)
    ai_analysis = load_ai_analysis(user_dir)

    # Merge AI analysis fields into undetect items
    for item in undetect:
        sub = item.get("subdomain", "").strip().lower()
        analysis = ai_analysis.get(sub)
        if analysis:
            item["potential"] = analysis["potential"]
            item["reason"] = analysis["reason"]
            item["ai_reference"] = analysis["reference"]
        else:
            item["potential"] = "Unanalyz"
            item["reason"] = ""
            item["ai_reference"] = ""

    total_vuln_subs = sum(len(v) for v in vulns.values())
    return {
        "vulns": vulns,
        "undetect": undetect,
        "service_map": service_map,
        "stats": {
            "total_vuln_subdomains": total_vuln_subs,
            "total_vuln_services": len(vulns),
            "total_undetect": len(undetect),
        },
    }



