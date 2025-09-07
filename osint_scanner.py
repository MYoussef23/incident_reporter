"""
OSINT Scanner (AbuseIPDB + VirusTotal)
--------------------------------------
A Fire-powered CLI for SOC analysts to validate and enrich indicators
(IPs, domains, file hashes). Skips internal/network-owned indicators via
org domain/CIDR allowlists, queries AbuseIPDB and VirusTotal, and prints
concise, analyst-friendly summaries. Supports optional CSV export for
each command so results can be saved and shared easily.

Attribution:
This module was inspired by the OSINT_Scanner project created by Jade Hill
(https://github.com/jade-hill-sage/OSINT-Scanner), which provided the
foundation for AbuseIPDB and VirusTotal enrichment logic.
"""

import asyncio
import ipaddress
import re
import socket
import json
import os
import time
import csv
from collections import defaultdict
from typing import Iterable, List, Optional, Dict, Any

import requests
import vt  # pip install vt-py
from ipwhois import IPWhois  # pip install ipwhois
import beep  # local helper for audible notifications (optional)

# --- TLS warnings (explicitly disabled; set VERIFY_TLS=True to re-enable) ---
import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

VERIFY_TLS = False  # AbuseIPDB often used with verify=False in your original script


# =============================================================================
# Validation helpers
# =============================================================================
def get_org_cidrs() -> list[ipaddress._BaseNetwork]:
    """
    Prompt user to enter their organisation's public network ranges in CIDR notation.
    These ranges will be excluded from AbuseIPDB lookups.
    """
    cidrs: list[ipaddress._BaseNetwork] = []
    try:
        beep.beep()
    except Exception:
        pass

    print("Enter your organisation's public network range(s) in CIDR notation (e.g., 203.0.113.0/24).")
    print("To avoid unnecessary OSINT checks on your own IPs, any addresses within these ranges will be skipped.")
    print("Enter one per line. Press Enter on a blank line to finish:")

    while True:
        cidr = input("CIDR: ").strip()
        if not cidr:
            break
        try:
            cidrs.append(ipaddress.ip_network(cidr))
        except ValueError:
            print("❌ Invalid CIDR, please try again.")
    return cidrs


def validate_IP(ip: str, org_cidrs: Optional[Iterable[ipaddress._BaseNetwork]] = None) -> bool:
    """
    True if IP is public and not inside any provided org_cidrs.
    False if private/invalid or within org_cidrs.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if org_cidrs:
            for net in org_cidrs:
                if ip_obj in net:
                    return False
        return ip_obj.is_global
    except ValueError:
        return False


def resolve_domain_to_ips(domain: str) -> List[str]:
    try:
        result = socket.getaddrinfo(domain, None)
        return list({entry[4][0] for entry in result})
    except Exception:
        return []


def validate_domain(
    domain: str,
    org_domains: Optional[Iterable[str]] = None,
    org_cidrs: Optional[Iterable[ipaddress._BaseNetwork]] = None,
) -> bool:
    """
    Basic syntax + resolves + not in org_domains + does not resolve to org_cidrs.
    """
    pattern = re.compile(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")
    if not pattern.fullmatch(domain):
        return False

    d = domain.lower()
    if org_domains:
        for od in org_domains:
            od = od.lower()
            if d == od or d.endswith("." + od) or od.endswith("." + d):
                return False

    ips = resolve_domain_to_ips(domain)
    if not ips:
        return False

    if org_cidrs:
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if any(ip_obj in cidr for cidr in org_cidrs):
                    return False
            except Exception:
                continue
    return True


def validate_hash(val: str) -> bool:
    v = val.lower()
    return (len(v) in (32, 40, 64)) and all(c in "0123456789abcdef" for c in v)


# =============================================================================
# VirusTotal (async) helpers
# =============================================================================
async def vt_fetch_file(api_key: str, file_hash: str):
    async with vt.Client(api_key) as client:
        return await client.get_object_async(f"/files/{file_hash}")


async def vt_fetch_domain(api_key: str, domain: str):
    async with vt.Client(api_key) as client:
        return await client.get_object_async(f"/domains/{domain}")


def vt_print_sandbox_verdict(file_object) -> str:
    if not file_object or not hasattr(file_object, "sandbox_verdicts"):
        print("No sandbox verdicts available.")
        return ""
    print("Sandbox Verdicts:")
    out = []
    for sandbox, verdict in file_object.sandbox_verdicts.items():
        cat = verdict.get("category", "Unknown")
        conf = verdict.get("confidence", "Unknown")
        sname = verdict.get("sandbox_name", "Unknown")
        mclass = ";".join(verdict.get("malware_classification", []))
        mnames = ";".join(verdict.get("malware_names", []))
        print(f"- Sandbox: {sandbox}")
        print(f"  Category: {cat}")
        print(f"  Confidence: {conf}%")
        print(f"  Sandbox Name: {sname}")
        if mclass:
            print(f"  Malware Classification: {mclass}")
        if mnames:
            print(f"  Malware Names: {mnames}")
        out.append(
            f"Sandbox:{sandbox};Category:{cat};Confidence:{conf};"
            f"Sandbox_Name:{sname};Malware_Classification:{mclass};Malware_Names:{mnames}"
        )
    return " | ".join(out)

def loop_domain_vt_check(api_key: str, domain_list: list[str], org_cidrs: list[str] | None = None):
    """
    Backward compatibility wrapper.
    Calls OSINTScanner.domain() and unpacks the result.
    """
    scanner = OSINTScanner()
    result = scanner.domain(targets=domain_list, 
                            vt_api_key=api_key,
                            org_cidrs=[str(c) for c in org_cidrs])
    return result["header"], result["rows"]

def loop_file_hash_vt_check(api_key: str, file_hash_list: list[str]):
    """
    Backward compatibility wrapper.
    Calls OSINTScanner.hash() and unpacks the result.
    """
    scanner = OSINTScanner()
    result = scanner.hash(targets=file_hash_list, vt_api_key=api_key)
    return result["header"], result["rows"]


# =============================================================================
# AbuseIPDB
# =============================================================================
def abuseipdb_check(ip_address: str, api_key: str) -> Dict[str, Any]:
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
    headers = {"Accept": "application/json", "Key": api_key}
    resp = requests.get(url, headers=headers, params=params, verify=VERIFY_TLS, timeout=30)
    try:
        return resp.json()
    except Exception:
        return {"error": f"Invalid response: {resp.status_code}", "text": resp.text[:2000]}


def whois_inetnum_cidr(ip: str) -> Optional[str]:
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        return results.get("network", {}).get("cidr")
    except Exception as e:
        print(f"WHOIS lookup failed for {ip}: {e}")
        return None

def loop_abuseIP_check(api_key: str, ip_list: list[str], org_cidrs: list[str] | None = None):
    """
    Backward compatibility wrapper.
    Calls OSINTScanner.ip() and unpacks the result.
    """
    org_cidrs = get_org_cidrs()
    scanner = OSINTScanner()
    result = scanner.ip(targets=ip_list, 
                        abuseipdb_api_key=api_key, 
                        org_cidrs=[str(c) for c in org_cidrs], 
                        print_json=False)
    return result["header"], result["rows"], org_cidrs, result["skipped_by_cidr"]

# =============================================================================
# CSV helper
# =============================================================================
def _write_csv(path: str, header: List[str], rows: List[List[Any]]) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if header:
            writer.writerow(header)
        writer.writerows(rows)
    print(f"[CSV] Wrote {len(rows)} row(s) to {path}")
    return path


# =============================================================================
# Fire CLI
# =============================================================================
class OSINTScanner:
    """
    OSINT Scanner CLI (Fire)
    - ip(...)     -> AbuseIPDB enrichment with per-CIDR skip de-duplication
    - domain(...) -> VirusTotal domain enrichment with org-domain/CIDR filtering
    - hash(...)   -> VirusTotal file hash enrichment and sandbox verdicts
    """

    # ---------- Common parse helpers ----------
    @staticmethod
    def _parse_cidrs(org_cidrs: Optional[Iterable[str]]) -> List[ipaddress._BaseNetwork]:
        nets: List[ipaddress._BaseNetwork] = []
        if org_cidrs:
            for c in org_cidrs:
                try:
                    if isinstance(c, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                        nets.append(c)
                    else:
                        nets.append(ipaddress.ip_network(str(c).strip()))
                except Exception:
                    print(f"Invalid CIDR skipped: {c}")
        return nets

    @staticmethod
    def _parse_domains(org_domains: Optional[Iterable[str]]) -> List[str]:
        return [d.strip().lower() for d in (org_domains or []) if d.strip()]

    # ---------- IP Mode ----------
    def ip(
        self,
        targets: Iterable[str],
        abuseipdb_api_key: Optional[str] = None,
        org_cidrs: Optional[Iterable[str]] = None,
        audible: bool = False,
        print_json: bool = True,
        output_csv: Optional[str] = None,
    ):
        """
        Check IPs against AbuseIPDB. Skips additional IPs in already-checked CIDRs.
        Args:
          targets: List of IPs.
          abuseipdb_api_key: API key or env ABUSEIPDB_KEY.
          org_cidrs: CIDR list to skip (your public ranges).
          audible: Beep when starting.
          print_json: Pretty-print API JSON results.
          output_csv: If provided, write results to this CSV path.
        """
        if audible:
            try:
                beep.beep()
            except Exception:
                pass

        api_key = abuseipdb_api_key or os.getenv("ABUSEIPDB_KEY")
        if not api_key:
            raise SystemExit("Error: supply --abuseipdb_api_key or set ABUSEIPDB_KEY.")

        nets = self._parse_cidrs(org_cidrs)
        header: Optional[List[str]] = None
        rows: List[List[Any]] = []
        already_checked_cidrs: set[str] = set()
        skipped_by_cidr: Dict[str, List[str]] = defaultdict(list)

        for ip in targets:
            if not validate_IP(ip, nets):
                continue
            cidr = whois_inetnum_cidr(ip)
            if cidr and cidr in already_checked_cidrs:
                skipped_by_cidr[cidr].append(ip)
                print(f"Skipped {ip}: CIDR {cidr} already analyzed.")
                continue

            print(f"Checking IP: {ip}")
            data = abuseipdb_check(ip, api_key)
            if print_json:
                print(json.dumps(data, indent=2))

            if "data" in data:
                if header is None:
                    header = list(data["data"].keys())
                row = [data["data"].get(k, "") for k in header]
                rows.append(row)
                if cidr:
                    already_checked_cidrs.add(cidr)
            else:
                print(f"Failed to retrieve data for IP: {ip} -> {data.get('error') or 'unknown error'}")

            time.sleep(0.5)

        print("\nAbuseIPDB Results:")
        print(header or [])
        for r in rows:
            print(r)
        if skipped_by_cidr:
            print("Skipped IPs by CIDR:", dict(skipped_by_cidr))

        if output_csv and header:
            _write_csv(output_csv, header, rows)

        return {"header": header or [], "rows": rows, "skipped_by_cidr": skipped_by_cidr}

    # ---------- Domain Mode ----------
    def domain(
        self,
        targets: Iterable[str],
        vt_api_key: Optional[str] = None,
        org_domains: Optional[Iterable[str]] = None,
        org_cidrs: Optional[Iterable[str]] = None,
        audible: bool = False,
        output_csv: Optional[str] = None,
    ):
        """
        Check domains with VirusTotal, excluding your org domains and domains
        resolving into your org CIDRs.
        Args:
          targets: Domain list.
          vt_api_key: API key or env VT_API_KEY.
          org_domains: Domains to treat as internal (skip).
          org_cidrs: Public CIDR list (skip domains that resolve into these).
          audible: Beep when starting.
          output_csv: If provided, write results to this CSV path.
        """
        if audible:
            try:
                beep.beep()
            except Exception:
                pass

        api_key = vt_api_key or os.getenv("VT_API_KEY")
        if not api_key:
            raise SystemExit("Error: supply --vt_api_key or set VT_API_KEY.")

        nets = self._parse_cidrs(org_cidrs)
        ods = self._parse_domains(org_domains)

        header: Optional[List[str]] = None
        rows: List[List[Any]] = []

        for domain in targets:
            if not validate_domain(domain, ods, nets):
                continue

            print(f"Checking Domain: {domain}")
            try:
                outcome = asyncio.run(vt_fetch_domain(api_key, domain))
            except Exception as e:
                print(f"Domain lookup failed for {domain}: {e}")
                continue

            if outcome:
                if header is None:
                    header = ["id", "type", "link", "stats", "last_analysis_date"]
                stats = getattr(outcome, "last_analysis_stats", {}) or {}
                stats_str = ";".join(f"{k}:{v}" for k, v in stats.items())
                link = f"https://www.virustotal.com/gui/domain/{domain}"
                row = [outcome.id, outcome.type, link, stats_str, getattr(outcome, "last_analysis_date", "N/A")]
                rows.append(row)

                print(f"-------- Results for Domain: {domain} --------")
                print(f"ID: {outcome.id}")
                print(f"Type: {outcome.type}")
                print(f"Link: {link}")
                print(f"Last Analysis Statistics: {stats}")
                print(f"Last Analysis Date: {getattr(outcome, 'last_analysis_date', 'N/A')}")
            else:
                print(f"Failed to retrieve data for domain: {domain}")

            time.sleep(0.5)

        print("\nVirusTotal Domain Results:")
        print(header or [])
        for r in rows:
            print(r)

        if output_csv and header:
            _write_csv(output_csv, header, rows)

        return {"header": header or [], "rows": rows}

    # ---------- Hash Mode ----------
    def hash(
        self,
        targets: Iterable[str],
        vt_api_key: Optional[str] = None,
        audible: bool = False,
        output_csv: Optional[str] = None,
    ):
        """
        Check file hashes with VirusTotal and print sandbox verdicts (if any).
        Args:
          targets: File hash list (MD5/SHA1/SHA256).
          vt_api_key: API key or env VT_API_KEY.
          audible: Beep when starting.
          output_csv: If provided, write results to this CSV path.
        """
        if audible:
            try:
                beep.beep()
            except Exception:
                pass

        api_key = vt_api_key or os.getenv("VT_API_KEY")
        if not api_key:
            raise SystemExit("Error: supply --vt_api_key or set VT_API_KEY.")

        header: Optional[List[str]] = None
        rows: List[List[Any]] = []

        for h in targets:
            if not validate_hash(h):
                print(f"Skipping invalid hash: {h}")
                continue

            print(f"Checking file hash: {h}")
            try:
                file_obj = asyncio.run(vt_fetch_file(api_key, h))
            except Exception as e:
                print(f"Error fetching info for file hash {h}: {e}")
                continue

            if file_obj:
                if header is None:
                    header = [
                        "file_hash",
                        "filename",
                        "file_type",
                        "file_size",
                        "last_analysis_stats",
                        "sandbox_verdict",
                        "last_analysis_date",
                    ]
                filename = getattr(file_obj, "meaningful_name", "")
                file_type = getattr(file_obj, "type_description", "")
                file_size = getattr(file_obj, "size", "")
                last_analysis_stats = getattr(file_obj, "last_analysis_stats", {}) or {}
                stats_str = ";".join(f"{k}:{v}" for k, v in last_analysis_stats.items())
                last_analysis_date = getattr(file_obj, "last_analysis_date", "")
                sbox = vt_print_sandbox_verdict(file_obj)

                row = [h, filename, file_type, file_size, stats_str, sbox, last_analysis_date]
                rows.append(row)

                print(f"-------- Results for File Hash: {h} --------")
                print(f"Filename: {filename}")
                print(f"File Type: {file_type}")
                print(f"File Size: {file_size}")
                print(f"Last Analysis Statistics: {stats_str}")
                print(f"Last Analysis Date: {last_analysis_date}")
            else:
                print(f"Failed to retrieve data for file hash: {h}")

            time.sleep(0.5)

        print("\nVirusTotal Hash Results:")
        print(header or [])
        for r in rows:
            print(r)

        if output_csv and header:
            _write_csv(output_csv, header, rows)

        return {"header": header or [], "rows": rows}


if __name__ == "__main__":
    # pip install fire
    import fire
    fire.Fire(OSINTScanner)
# =============================================================================
# Example usage:
#   python osint_scanner.py ip --targets
#   python osint_scanner.py domain --targets
#   python osint_scanner.py hash --targets
#   python osint_scanner.py ip --targets 8.8.8.8 1.1.1.1 --org_cidrs 203.0.113.0/24 198.51.100.0/24 --output_csv results/abuseipdb_ips.csv
#   python osint_scanner.py domain --targets example.com test.org --org_domains example.com --output_csv results/vt_domains.csv
#   python osint_scanner.py hash --targets d41d8cd98f00b204e9800998ecf8427e --output_csv results/vt_hashes.csv
# =============================================================================

