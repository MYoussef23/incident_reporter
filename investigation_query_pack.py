import re
import ast
import ipaddress
from urllib.parse import urlparse
from collections import defaultdict
from typing import Dict, Any, Iterable, List, Tuple
import json
import yaml

def load_queries(yaml_path: str) -> dict:
    with open(yaml_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

# Load once at start
QUERIES = load_queries("config.yaml")

_IPv4_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b')
_IPv6_RE = re.compile(r'\b(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|:(?::[A-Fa-f0-9]{1,4}){1,7}|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6})\b')
_URL_RE = re.compile(r'\bhttps?://[^\s"\'<>]+', re.IGNORECASE)
# Loose domain matcher (skip pure IPs and URLs; we’ll filter later)
_DOMAIN_RE = re.compile(r'\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,63})\b')
# UPN / email-like
_UPN_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}\b')
# Hostnames (single-label or multi-label; excludes things that look like domains with TLD already captured)
_HOST_RE = re.compile(r'\b(?!(?:https?://))(?!(?:\d{1,3}\.){3}\d{1,3}\b)[A-Za-z0-9][A-Za-z0-9\-]{0,62}(?:\.[A-Za-z0-9\-]{1,63})*\b')
# Hashes
_MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
_SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
# Ports (find numbers following common tokens or :port)
_PORT_RE = re.compile(r'(?:(?:dst|dest|destination|dport|port)\s*[:=]\s*|:)(\d{1,5})', re.IGNORECASE)
# Simple protocol/app-proto grab (from CommonSecurityLog/CEF or KQL)
_PROTO_RE = re.compile(r'\b(?:TCP|UDP|ICMP|HTTP|HTTPS|DNS|LDAP|RDP|SMB|SSH|FTP|SIP|TELNET|NTP|Kerberos|DHCP|IMAP|POP3|SMTP)\b', re.IGNORECASE)

def _safe_literal_list(text: str) -> Iterable[str]:
    """
    If 'text' contains a JSON/Python-like list (e.g., ["1.2.3.4"]), return its items.
    Otherwise return an empty list.
    """
    try:
        t = text.strip()
        if t.startswith('[') and t.endswith(']'):
            val = ast.literal_eval(t)
            if isinstance(val, (list, tuple)):
                return [str(x) for x in val]
    except Exception:
        pass
    return []

def _classify_ip(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            return "internal"
        return "external"
    except ValueError:
        return "unknown"

def _extract_from_text(s: str) -> Dict[str, Any]:
    found = {
        "ips_external": set(),
        "ips_internal": set(),
        "urls": set(),
        "domains": set(),
        "users": set(),
        "hosts": set(),
        "ports": set(),
        "protocols": set(),
        "hashes": set(),
    }
    if not s:
        return found

    # URLs
    for u in _URL_RE.findall(s):
        found["urls"].add(u)
        # Extract domain from URL
        try:
            netloc = urlparse(u).netloc
            if netloc:
                # strip port from netloc
                host = netloc.split('@')[-1].split(':')[0]
                if _IPv4_RE.fullmatch(host):
                    cls = _classify_ip(host)
                    if cls == "external":
                        found["ips_external"].add(host)
                    elif cls == "internal":
                        found["ips_internal"].add(host)
                else:
                    found["domains"].add(host.lower())
        except Exception:
            pass

    # IPs (v4 + v6)
    for ip in _IPv4_RE.findall(s):
        cls = _classify_ip(ip)
        (found["ips_internal"] if cls == "internal" else found["ips_external"]).add(ip) if cls in ("internal", "external") else None
    for ip in _IPv6_RE.findall(s):
        # classify v6 as internal if private (ULA fc00::/7) or link-local
        cls = _classify_ip(ip)
        if cls == "internal":
            found["ips_internal"].add(ip)
        elif cls == "external":
            found["ips_external"].add(ip)

    # Domains (exclude ones already part of URLs)
    for d in _DOMAIN_RE.findall(s):
        if not _IPv4_RE.fullmatch(d):
            found["domains"].add(d.lower())

    # Users / UPNs
    for upn in _UPN_RE.findall(s):
        found["users"].add(upn.lower())

    # Hostnames (coarse; we’ll prune those that look like pure TLD domains already captured)
    for h in _HOST_RE.findall(s):
        # Heuristic: treat as host if it contains a dash, digits+letters mix, or is short single-label used often for devices
        if '.' not in h or h.lower() not in found["domains"]:
            # Avoid collecting obvious keywords accidentally matched
            if len(h) <= 63 and not h.lower().startswith(("http", "select", "where", "join", "union")):
                found["hosts"].add(h)

    # Ports
    for p in _PORT_RE.findall(s):
        try:
            num = int(p)
            if 0 < num <= 65535:
                found["ports"].add(num)
        except Exception:
            pass

    # Protocols
    for proto in _PROTO_RE.findall(s):
        found["protocols"].add(proto.upper())

    # Hashes
    for h in _SHA256_RE.findall(s):
        found["hashes"].add(("SHA256", h.lower()))
    for h in _SHA1_RE.findall(s):
        found["hashes"].add(("SHA1", h.lower()))
    for h in _MD5_RE.findall(s):
        found["hashes"].add(("MD5", h.lower()))

    # If there are embedded JSON-like lists, parse and recurse a bit
    for item in _safe_literal_list(s):
        sub = _extract_from_text(str(item))
        for k in found:
            found[k].update(sub[k])

    return found

def _to_text_chunks(obj: Any) -> list[str]:
    """Flatten obj into a list of strings (handles str, dict, list, tuples, etc.)."""
    chunks = []
    def add(x: Any):
        if x is None:
            return
        if isinstance(x, (str, bytes)):
            chunks.append(x.decode() if isinstance(x, bytes) else x)
        elif isinstance(x, dict):
            # stringify dicts so keys/values are searchable
            chunks.append(json.dumps(x, default=str))
        elif isinstance(x, (list, tuple, set)):
            for i in x:
                add(i)
        else:
            chunks.append(str(x))
    add(obj)
    return chunks

def extract_entities(incident_title: str, detection_results: Iterable[Any]) -> Dict[str, Any]:
    """
    Parse entities from incident title, detection query (KQL/CEF/JSON fragments), and alert rows.
    Returns a normalized structure for downstream query routing.
    """
    # Base container
    entities = {
        "users": set(),
        "ips": {"external": set(), "internal": set()},
        "hosts": set(),
        "domains": set(),
        "urls": set(),
        "ports": set(),
        "protocols": set(),
        "hashes": set(),   # tuples of (algo, value)
    }

    # Aggregate text sources
    corpus = [incident_title or ""]
    corpus.extend(_to_text_chunks(detection_results))

    # Extract from each piece
    for chunk in corpus:
        found = _extract_from_text(chunk)
        entities["users"].update(found["users"])
        entities["ips"]["external"].update(found["ips_external"])
        entities["ips"]["internal"].update(found["ips_internal"])
        entities["hosts"].update(found["hosts"])
        entities["domains"].update(found["domains"])
        entities["urls"].update(found["urls"])
        entities["ports"].update(found["ports"])
        entities["protocols"].update(found["protocols"])
        entities["hashes"].update(found["hashes"])

    # Light normalization / pruning
    # Remove domains that are actually IPs
    entities["domains"] = {d for d in entities["domains"] if not _IPv4_RE.fullmatch(d)}
    # Drop hosts that look exactly like domains we already captured
    entities["hosts"] = {h for h in entities["hosts"] if h.lower() not in entities["domains"]}

    return entities

def build_query_pack(entities, start, end, hints):
    pack = []
    upns = sorted(set(entities.get("users", [])))[:5]
    if not upns:
        return pack

    for upn in upns:
        pack.append((
            f"IdentityInfo_{upn}",
            QUERIES["identity_info"].format(UserPrincipalName=upn, start=start, end=end)
        ))
        pack.append((
            f"SigninLogsInteractive_{upn}",
            QUERIES["signin_interactive"].format(UserPrincipalName=upn, start=start, end=end)
        ))
        pack.append((
            f"SigninLogsNonInteractive_{upn}",
            QUERIES["signin_noninteractive"].format(UserPrincipalName=upn, start=start, end=end)
        ))

    dq = (hints.get("detection_query") or "").lower()
    if "officeactivity" in dq or hints.get("force_office_activity"):
        ops_hint = hints.get("office_operations")
        if not ops_hint or (isinstance(ops_hint, str) and ops_hint.lower() == "all"):
            ops_list = []
        elif isinstance(ops_hint, str):
            ops_list = [s.strip() for s in ops_hint.split(",") if s.strip()]
        else:
            ops_list = list(ops_hint)
        ops_json = json.dumps(ops_list)

        for upn in upns:
            pack.append((
                f"OfficeActivity_{upn}",
                QUERIES["office_activity"].format(UserPrincipalName=upn, OperationsJSON=ops_json, start=start, end=end)
            ))

    return pack