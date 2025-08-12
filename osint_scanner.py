import asyncio
import ipaddress
import re
import socket
import vt
import json
import requests
from ipwhois import IPWhois
from collections import defaultdict
import argparse
import sys
import beep

### This module is inspired from script, OSINT_Scanner, created by Jade Hill (GitHub repo: https://github.com/jade-hill-sage/OSINT-Scanner) for performing OSINT checks in AbuseIPDB and VirusTotal.    

# ------------ IP Validation ------------ #

def validate_IP(ip, org_cidrs=None):    # Checks if an IP is public/private/invalid - returns false if not public (private/invalid)
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Check if it's in any of the org's public CIDRs
        if org_cidrs:
            for net in org_cidrs:
                if ip_obj in net:
                    # IP is in org's range; skip validation (return False to skip API call)
                    return False
        # Otherwise, return True only if IP is public (not private)
        # Only consider as "public" if is_global (not private, not reserved, not loopback, not link-local)
        return ip_obj.is_global
    except ValueError:
        return False

# ------------ Domain Validation ------------ #

def resolve_domain_to_ips(domain):
    try:
        result = socket.getaddrinfo(domain, None)
        ips = set()
        for entry in result:
            ip = entry[4][0]
            ips.add(ip)
        return list(ips)
    except Exception:
        return []

def validate_domain(domain, org_domains=None, org_cidrs=None):
    """
    Returns True if domain is valid, resolves, is not in org_domains,
    and does not resolve to org CIDRs.
    """
    domain_pattern = re.compile(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")  # Basic domain validation regex
    if not domain_pattern.fullmatch(domain):
        return False
    
    # If org_domains is provided and matches, treat as internal/corporate
    if org_domains:
        d = domain.lower()
        for od in org_domains:
            if d == od.lower() or d.endswith("." + od.lower()) or od.lower().endswith("." + d):
                return False
    
    # DNS resolution
    ips = resolve_domain_to_ips(domain)
    if not ips:
        return False
    
    # If org_cidrs provided, check if any IP falls in org range
    if org_cidrs:
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for cidr in org_cidrs:
                    if ip_obj in cidr:
                        return False  # Domain resolves to internal IP, treat as internal
            except Exception:
                continue
            
    return True

# ------------ Hash Validation ------------ #

def validate_hash(val):
    val = val.lower()
    return (
        len(val) in [32, 40, 64] and 
        all(c in "0123456789abcdef" for c in val)
    )
    
# ------------ VirusTotal File Hash Functions ------------ #

async def fetch_file_info(api_key, file_hash):
    async with vt.Client(api_key) as client: 
        try:
            file_object = client.get_object(f"/files/{file_hash}")
            return file_object
        except vt.error.APIError as e:
            print(f"Error fetching info for file hash: {e}")
            return None

def print_sandbox_verdict(file_object):
    if not file_object or not hasattr(file_object, "sandbox_verdicts"):
        print("No sandbox verdicts available.")
        return
    print("Sandbox Verdicts:")
    sandbox_verdicts = file_object.sandbox_verdicts
    for sandbox, verdict in sandbox_verdicts.items():
        print(f"- Sandbox: {sandbox}")
        category = verdict.get('category', 'Unknown')
        print(f"  Category: {category}")
        confidence = verdict.get('confidence', 'Unknown')
        print(f"  Confidence: {confidence}%")
        sandbox_name = verdict.get('sandbox_name', 'Unknown')
        print(f"  Sandbox Name: {sandbox_name}")
        malware_classification = ';'.join(verdict.get('malware_classification', []))
        if malware_classification:
            print(f"  Malware Classification: {malware_classification}")
        malware_names = ';'.join(verdict.get('malware_names', []))
        if malware_names:
            print(f"  Malware Names: {malware_names}")
        print()
    
    sandbox_verdicts_output = f"Sandbox:{sandbox};Category:{category};Confidence:{confidence};Sandbox_Name:{sandbox_name};Malware_Classification:{malware_classification};Malware_Names:{malware_names}"
    return sandbox_verdicts_output

def loop_file_hash_vt_check(api_key, file_hashes, header=None):
    rows = []
    for file_hash in file_hashes:
        print(f"Checking file hash: {file_hash}")
        file_info = asyncio.run(fetch_file_info(api_key, file_hash))
        if file_info:
            if header is None:
                header = ['file_hash', 'filename', 'file_type', 'file_size', 'last_analysis_stats', 'sandbox_verdict', 'last_analysis_date']
            # Prepare values
            filename = getattr(file_info, 'meaningful_name', '')
            file_type = getattr(file_info, 'type_description', '')
            file_size = getattr(file_info, 'size', '')
            last_analysis_stats = getattr(file_info, 'last_analysis_stats', {})
            stats_str = ';'.join(f"{k}:{v}" for k, v in last_analysis_stats.items())
            last_analysis_date = getattr(file_info, 'last_analysis_date', '')
            sandbox_verdict = print_sandbox_verdict(file_info)
            row = [file_hash, filename, file_type, file_size, stats_str, sandbox_verdict, last_analysis_date]
            rows.append(row)
            # Print details for debugging/console
            print(f'-------- Results for File Hash: {file_hash} --------')
            print(f'Filename: {filename}')
            print(f'File Type: {file_type}')
            print(f'File Size: {file_size}')
            print(f'Last Analysis Statistics: {stats_str}')
            print(f'Last Analysis Date: {last_analysis_date}')
            print_sandbox_verdict(file_info)
        else:
            print(f"Failed to retrieve data for file hash: {file_hash}")
    return header, rows

# ------------ VirusTotal Domain Functions ------------ #

def get_org_domains():
    domains = []
    beep.beep()     # Play a notification sound for user attention
    print("Enter your organisation's corporate domain(s) (e.g., company.com). Any domains you list here will be excluded from OSINT checks to avoid unnecessary analysis your own corporate domains.")
    print("Enter one per line. Press Enter on a blank line to finish:")
    while True:
        domain = input("Domain: ").strip().lower()
        if not domain:
            break
        # Basic check for valid domain format
        if not re.fullmatch(r"(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}", domain):
            print("Invalid domain, please try again.")
            continue
        domains.append(domain)
    return domains

async def fetch_domain_info(api_key, domain):
    async with vt.Client(api_key) as client:
        try:
            vt_obj = client.get_object(f'/domains/{domain}')
            #print(vt_obj.to_dict())
            return vt_obj
        except vt.error.APIError as e:
            print(f"Error retrieving data for {domain}: {e}")
            return None

def loop_domain_vt_check(api_key, domains, header=None, org_cidrs=None):
    if org_cidrs is None:
        org_domains = get_org_domains()      # Get the org corp domain to exclude in domain abuse analysis
    else:
        org_domains = None
    rows = []
    for domain in domains:
        is_not_org_domain=validate_domain(domain, org_domains, org_cidrs)    # Check if the domain is not an org domain
        if is_not_org_domain:   # Complete domain abuse check if domain is not the org domain
            print(f"Checking Domain: {domain}")
            outcome = asyncio.run(fetch_domain_info(api_key, domain))
            if outcome:
                # Prepare header and results
                if header is None:
                    header = ['id', 'type', 'link', 'stats', 'last_analysis_date']
                # Format stats as a single string: key1:val1;key2:val2
                stats = getattr(outcome, "last_analysis_stats", {})
                stats_str = ';'.join(f"{k}:{v}" for k, v in stats.items()) 
                link = f"https://www.virustotal.com/gui/domain/{domain}"
                row = [outcome.id, outcome.type, link, stats_str, getattr(outcome, "last_analysis_date", "N/A")]
                rows.append(row)
                # Print the URL info in json format
                print(f'-------- Results for Domain: {domain} --------')
                print(f'ID: {outcome.id}')
                print(f'Type: {outcome.type}')
                print(f'Link: {link}')
                print(f'Last Analysis Statistics: {stats}')
                print(f'Last Analysis Date: {getattr(outcome, "last_analysis_date", "N/A")}')
            else:
                print(f"Failed to retrieve data for domain: {domain}")
    return header, rows

# ------------ AbuseIPDB Functions ------------ #

def get_inetnum(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        net = results.get('network', {})
        inetnum = net.get('cidr')
        return inetnum
    except Exception as e:
        print(f"WHOIS lookup failed for {ip}: {e}")
        return None

def get_org_cidrs(): # The user will be able to input their orgs public network range to avoid unnecessary OSINT checks.
    cidrs = []
    beep.beep()     # Play a notification sound for user attention
    print("Enter your organisation's public network range(s) in CIDR notation (e.g., 203.0.113.0/24). To avoid unnecessary OSINT checks on your own IPs, any addresses within these ranges will be skipped.")
    print("Enter one per line. Press Enter on a blank line to finish:")
    while True:
        cidr = input("CIDR: ").strip()
        if not cidr:
            break
        try:
            cidrs.append(ipaddress.ip_network(cidr))
        except ValueError:
            print("Invalid CIDR, please try again.")
    return cidrs

def abuseIP_check(ip_address, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        f'ipAddress': f'{ip_address}',
        'maxAgeInDays': '90'}
    headers = {
        'Accept': 'application/json',
        'Key': f'{api_key}'}
    response = requests.request(method='GET', url=url, headers=headers, params=querystring, verify=False)
    return json.loads(response.text)

def loop_abuseIP_check(api_key, ip_address, header=None):
    org_cidrs = get_org_cidrs()     # Get the org network range to exclude in IP abuse analysis
    rows = []
    already_checked_cidrs = set()
    skipped_ips_by_cidr = defaultdict(list)  # for the report
    for ip in ip_address:
        is_not_org_ip=validate_IP(ip, org_cidrs)    # Check if the IP is not an org IP
        if is_not_org_ip:   # Complete IP abuse check if IP does not belong to the org IP range
            cidr = get_inetnum(ip)      # Get the CIDR of the IP address
            if cidr not in already_checked_cidrs:   # If CIDR of the IP address is not on the list
                print(f"Checking IP: {ip}")
                outcome = abuseIP_check(ip, api_key)
                if outcome and 'data' in outcome:
                    print(json.dumps(outcome, indent=2))    # Print the results
                    if header is None:
                        header = list(outcome['data'].keys())
                    row = [outcome['data'].get(key, "") for key in header]
                    rows.append(row)
                    already_checked_cidrs.add(cidr)     # Add to already checked IP within CIDR
                else:
                    print(f"Failed to retrieve data for IP: {ip}")
            else:
               skipped_ips_by_cidr[cidr].append(ip)
               print(f"Abuse check skipped for IP {ip}: its network range ({cidr}) has already been analysed.")
    
    return header, rows, org_cidrs, skipped_ips_by_cidr

def main():
    parser = argparse.ArgumentParser(
        description="OSINT Scanner for IPs, domains, and hashes using AbuseIPDB and VirusTotal."
    )
    parser.add_argument("--mode", required=True, choices=["ip", "domain", "hash"], help="Scan mode: ip, domain, or hash")
    parser.add_argument("--targets", nargs="+", required=True, help="Space-separated list of IPs, domains, or hashes")
    parser.add_argument("--vt-api-key", help="VirusTotal API Key (required for domain/hash modes)")
    parser.add_argument("--abuseipdb-api-key", help="AbuseIPDB API Key (required for ip mode)")

    args = parser.parse_args()

    # IP mode
    if args.mode == "ip":
        if not args.abuseipdb_api_key:
            print("Error: --abuseipdb-api-key is required for IP mode.")
            sys.exit(1)
        header, rows, org_cidrs, skipped_ips_by_cidr = loop_abuseIP_check(
            args.abuseipdb_api_key, args.targets
        )
        print("\nAbuseIPDB Results:")
        print(header)
        for row in rows:
            print(row)
        if skipped_ips_by_cidr:
            print("Skipped IPs by CIDR:", dict(skipped_ips_by_cidr))

    # Domain mode
    elif args.mode == "domain":
        if not args.vt_api_key:
            print("Error: --vt-api-key is required for domain mode.")
            sys.exit(1)
        header, rows = loop_domain_vt_check(args.vt_api_key, args.targets)
        print("\nVirusTotal Domain Results:")
        print(header)
        for row in rows:
            print(row)

    # Hash mode
    elif args.mode == "hash":
        if not args.vt_api_key:
            print("Error: --vt-api-key is required for hash mode.")
            sys.exit(1)
        header, rows = loop_file_hash_vt_check(args.vt_api_key, args.targets)
        print("\nVirusTotal Hash Results:")
        print(header)
        for row in rows:
            print(row)

if __name__ == "__main__":
    main()
