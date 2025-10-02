
"""
Incident Reporter Tool
----------------------
An automation-focused SOC investigation assistant that generates structured 
HTML reports for security incidents. It integrates with Azure Monitor Logs 
and CSV data, runs OSINT enrichment (AbuseIPDB, VirusTotal), performs MITRE 
ATT&CK mapping via local LLM (Ollama), and outputs analyst-ready reports. 

Designed to streamline SOC workflows by combining query execution, indicator 
extraction, enrichment, and documentation into a single tool.
"""


from __future__ import annotations

import json
import logging
import os
import platform
import re
import sys
import time
from html import escape
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

# --- Optional/3rd-party imports guarded ---
try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # Will error only if YAML is actually requested

try:
    import pandas as pd  # type: ignore
except Exception as e:  # pragma: no cover
    print("ERROR: pandas is required. pip install pandas")
    raise

try:
    from tkinter import Tk, filedialog  # type: ignore
    _HAS_TK = True
except Exception:
    _HAS_TK = False

try:
    import win32com.client  # type: ignore
    _HAS_WIN32COM = True
except Exception:
    _HAS_WIN32COM = False

try:
    import nest_asyncio  # type: ignore
    _HAS_NEST_ASYNCIO = True
except Exception:
    _HAS_NEST_ASYNCIO = False

# --- Project-local imports (assumed available) ---
from azure_monitor_cli import azure_monitor_login, _query_log_analytics, _extract_first_table
import iocextract  # type: ignore
import osint_scanner  # type: ignore
from get_mitre_attack_details import mitre_attack_html_section
from ollama_prompt import run_ollama
from beep import beep

# --- Constants ---
MITRE_VERSION: float = 17.1  # ATT&CK v17.1
REPORT_HTML = Path("report.html")
LOG_FORMAT = "%(levelname)s: %(message)s"

_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


# ----------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------
def setup_logging(verbose: bool = True) -> None:
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=level, format=LOG_FORMAT)


def prompt_yes_no(message: str) -> bool:
    """Prompt user with a yes/no question; returns True for yes."""
    while True:
        beep()
        ans = input(f"{message} (y/n): ").strip().lower()
        if ans in {"y", "yes"}:
            return True
        if ans in {"n", "no"}:
            return False
        beep()
        logging.error("Invalid input. Please enter 'y' or 'n'.")


def validate_workspace_id(workspace_id: str) -> bool:
    """Validate the Log Analytics workspace GUID format."""
    return bool(re.match(r"^[0-9a-fA-F-]{36}$", workspace_id or ""))

def validate_tenant_id(tenant_id: str) -> bool:
    """
    Validate an Azure tenant identifier.
    Accepts either a GUID (tenant ID) or a domain name (verified domain).
    """
    # GUID pattern (with dashes)
    guid_pattern = re.compile(
        r"^[0-9a-fA-F]{8}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{12}$"
    )

    # Simple domain pattern (e.g., contoso.com, qr.com.au)
    domain_pattern = re.compile(
        r"^(?=.{1,255}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
    )

    return bool(guid_pattern.match(tenant_id) or domain_pattern.match(tenant_id))


def format_elapsed(seconds: float) -> str:
    """Format elapsed time as M min S sec."""
    minutes = int(seconds // 60)
    sec = seconds % 60
    return f"{minutes}m {sec:.2f}s" if minutes > 0 else f"{sec:.2f}s"


def close_excel_with_file_open(filename_fragment: str) -> None:
    """
    Try to close any open Excel workbook containing 'filename_fragment' in its FullName.
    Only works on Windows when pywin32 is available.
    """
    if platform.system() != "Windows" or not _HAS_WIN32COM:
        return
    try:
        excel = win32com.client.GetActiveObject("Excel.Application")  # type: ignore
    except Exception:
        logging.info("Excel is not running; nothing to close.")
        return

    # enumerate first to avoid iterator invalidation
    workbooks = [wb for wb in excel.Workbooks]
    closed_any = False
    for wb in workbooks:
        try:
            fullname = str(wb.FullName).lower()
            if ".csv" in fullname and filename_fragment.lower() in fullname:
                path_print = wb.FullName
                wb.Close(SaveChanges=False)
                logging.info("Closed Excel workbook: %s", path_print)
                closed_any = True
        except Exception as e:  # pragma: no cover
            logging.warning("Could not close workbook: %s", e)

    try:
        if closed_any and excel.Workbooks.Count == 0:
            excel.Quit()
    except Exception:
        pass


# ----------------------------------------------------------------------------
# Config loading
# ----------------------------------------------------------------------------
def load_config(file_path: Union[str, Path]) -> Dict[str, Any]:
    """Load configuration from YAML or JSON file."""
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    data = file_path.read_text(encoding="utf-8")
    ext = file_path.suffix.lower()

    if ext in {".yaml", ".yml"}:
        if yaml is None:
            raise ImportError("PyYAML not installed. pip install pyyaml")
        try:
            cfg = yaml.safe_load(data)
            if not isinstance(cfg, dict):
                raise ValueError("YAML config root must be a mapping/object.")
            return cfg
        except Exception as e:
            raise ValueError(f"Error parsing YAML config: {e}")
    elif ext == ".json":
        try:
            cfg = json.loads(data)
            if not isinstance(cfg, dict):
                raise ValueError("JSON config root must be an object.")
            return cfg
        except Exception as e:
            raise ValueError(f"Error parsing JSON config: {e}")
    else:
        raise ValueError(f"Unsupported config extension: {ext}")


# ----------------------------------------------------------------------------
# IO helpers
# ----------------------------------------------------------------------------
def save_table_to_csv_and_preview_json(table: Dict[str, Any], filename_csv: Path, filename_json: Path) -> None:
    """Persist query 'table' as CSV and a JSON preview of the first 5 rows."""
    df = pd.DataFrame(table["rows"], columns=[c["name"] for c in table["columns"]])

    # Retry loop for CSV save (Excel locks)
    while True:
        try:
            df.to_csv(filename_csv, index=False, encoding="utf-8")
            logging.info("Saved CSV: %s", filename_csv)
            break
        except PermissionError as e:
            logging.warning("Could not write %s: %s", filename_csv, e)
            print("👉 Please close the file if it's open (e.g., in Excel).")
            choice = input("Press Enter to retry, or type 's' to skip saving CSV: ").strip().lower()
            if choice == "s":
                logging.info("Skipped saving CSV.")
                break
            time.sleep(1)

    try:
        df.head().to_json(filename_json, orient="records", indent=2, force_ascii=False)
        logging.info("Saved JSON preview: %s", filename_json)
    except Exception as e:
        logging.warning("Failed to save JSON preview: %s", e)


def select_csv_via_gui() -> Optional[Path]:
    """Open a file dialog to select a CSV; returns path or None if cancelled."""
    if not _HAS_TK:
        logging.error("tkinter not available in this environment.")
        return None
    try:
        Tk().withdraw()  # Hide the root window
        path = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        return Path(path) if path else None
    except Exception as e:
        logging.error("Failed to open file dialog: %s", e)
        return None


# ----------------------------------------------------------------------------
# IOC extraction and OSINT
# ----------------------------------------------------------------------------
def extract_iocs_in_data(csv_like_html: Union[str, List[str]]) -> Dict[str, List[str]]:
    """Extract IPs, domains, hashes from rendered CSV/HTML text chunks."""
    iocs = {"ips": set(), "domains": set(), "hashes": set()}

    def _process_chunk(chunk: str) -> None:
        cleaned = chunk.replace("<br />", ",")
        iocs["ips"].update(
            ip for ip in iocextract.extract_ips(cleaned)
            if osint_scanner.validate_IP(ip)
        )
        # Domains (exclude IPv4 lookalikes)
        domain_regex = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
        for d in set(re.findall(domain_regex, cleaned)):
            if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", d) and osint_scanner.validate_domain(d):
                iocs["domains"].add(d)
        iocs["hashes"].update(iocextract.extract_hashes(cleaned))

    if isinstance(csv_like_html, list):
        for s in csv_like_html:
            _process_chunk(str(s))
    elif isinstance(csv_like_html, str):
        _process_chunk(csv_like_html)
    else:
        raise TypeError("csv_like_html must be str or List[str]")

    return {k: sorted(v) for k, v in iocs.items()}

def osint_check(query_result_rendered: Union[str, List[str]], cfg: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Run AbuseIPDB + VirusTotal checks for extracted IOCs; return HTML segments."""
    ABIPDB_analysis = ""
    skipped_ip_analysis = ""
    domain_analysis = ""
    hash_analysis = ""

    VT_api_key = cfg.get("VT_api_key")
    ABDB_api_key = cfg.get("ABDB_api_key")

    logging.info("Extracting IOCs from data...")
    iocs = extract_iocs_in_data(query_result_rendered)
    ip_list = iocs.get("ips", [])
    domain_list = iocs.get("domains", [])
    file_hash_list = iocs.get("hashes", [])
    org_cidrs = None

    # AbuseIPDB: IPs
    if ip_list:
        logging.info("OSINT: checking IPs via AbuseIPDB (n=%d)", len(ip_list))
        header, rows, org_cidrs, skipped = osint_scanner.loop_abuseIP_check(ABDB_api_key, ip_list)
        if header and rows:
            ABIPDB_analysis = (
                "<p><a href=https://www.abuseipdb.com/>https://www.abuseipdb.com/</a> IP Analysis:</p>"
                + "<table border='1'>"
                + "<tr>" + "".join(f"<th>{escape(str(c))}</th>" for c in header) + "</tr>"
                + "".join("<tr>" + "".join(f"<td>{escape(str(cell))}</td>" for cell in row) + "</tr>" for row in rows)
                + "</table>"
            )
        # skipped
        if skipped:
            items = list(skipped.items())
            if len(items) == 1:
                cidr, ips = items[0]
                skipped_ip_analysis = (
                    f"<p>The following IPs were not individually checked as they belong to "
                    f"the already-analysed network range <strong>{escape(cidr)}</strong>: {', '.join(map(escape, ips))}.</p>"
                )
            else:
                skipped_ip_analysis = "<p>The following IPs were not individually checked as they belong to the already-analysed network ranges:</p><ul>"
                for cidr, ips in items:
                    skipped_ip_analysis += f"<li><strong>{escape(cidr)}</strong>: {', '.join(map(escape, ips))}</li>"
                skipped_ip_analysis += "</ul>"

    # VirusTotal: Domains
    if domain_list:
        logging.info("OSINT: checking domains via VirusTotal (n=%d)", len(domain_list))
        if org_cidrs is None:
            header, rows = osint_scanner.loop_domain_vt_check(VT_api_key, domain_list)
        else:
            header, rows = osint_scanner.loop_domain_vt_check(VT_api_key, domain_list, org_cidrs=org_cidrs)
        if header and rows:
            domain_analysis = (
                "<p><a href=https://www.virustotal.com/>https://www.virustotal.com/</a> Domain Analysis:</p>"
                + "<table border='1'>"
                + "<tr>" + "".join(f"<th>{escape(str(c))}</th>" for c in header) + "</tr>"
                + "".join("<tr>" + "".join(f"<td>{escape(str(cell))}</td>" for cell in row) + "</tr>" for row in rows)
                + "</table>"
            )

    # VirusTotal: File hashes
    if file_hash_list:
        logging.info("OSINT: checking file hashes via VirusTotal (n=%d)", len(file_hash_list))
        header, rows = osint_scanner.loop_file_hash_vt_check(VT_api_key, file_hash_list)
        if header and rows:
            hash_analysis = (
                "<p><a href=https://www.virustotal.com/>https://www.virustotal.com/</a> File Hash Analysis:</p>"
                + "<table border='1'>"
                + "<tr>" + "".join(f"<th>{escape(str(c))}</th>" for c in header) + "</tr>"
                + "".join("<tr>" + "".join(f"<td>{escape(str(cell))}</td>" for cell in row) + "</tr>" for row in rows)
                + "</table>"
            )

    return ABIPDB_analysis, skipped_ip_analysis, domain_analysis, hash_analysis

# ----------------------------------------------------------------------------
# Query results + alert handling
# ----------------------------------------------------------------------------
def get_incident_number() -> int:
    """Loop until a valid positive integer incident ID is entered."""
    while True:
        beep()
        s = input("Enter the Incident ID: ").strip()
        if s.isdigit():
            v = int(s)
            if v > 0:
                return v
        beep()
        logging.error("Invalid input. Sentinel incident numbers are positive integers.")


def get_valid_incident_id() -> int:
    """Ask for incident number, then confirm with user."""
    while True:
        incident_id = get_incident_number()
        beep()
        cont = input(f"Selected Incident ID: {incident_id}. Continue? (y/n): ").strip().lower()
        if cont in {"y", "yes"}:
            return incident_id
        if cont in {"n", "no"}:
            logging.info("Re-entering Incident ID...")
            continue
        beep()
        logging.error("Invalid input. Please enter 'y' or 'n'.")


def prepare_results(table: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Any]:
    """Convert table rows to alert dicts and return (alerts, first_alert_id)."""
    alerts: List[Dict[str, Any]] = []
    for row in table["rows"]:
        incident_title, product_name, alert_id, start_time_utc, end_time_utc, query, tactics, techniques = row
        logging.info("Alert: %s | %s | %s", incident_title, product_name, alert_id)

        alerts.append({
            "IncidentTitle": incident_title,
            "ProductName": product_name,
            "AlertId": alert_id,
            "StartTimeUTC": start_time_utc,
            "EndTimeUTC": end_time_utc,
            "Query": query,
            "Tactics": tactics,
            "Techniques": techniques,
        })
    return alerts, alerts[0]["AlertId"]

def run_detection_queries_on_alerts(
    alerts: Sequence[Dict[str, Any]],
    workspace_id: str,
    alert_link_query: str,
    tenant_id: Optional[str] = None
) -> Tuple[str, List[str], Any, Any, str, Optional[str], Optional[Path]]:
    """
    For Sentinel alerts, run detection queries and save results to CSV/JSON.
    For non-Sentinel alerts, fetch alert links.

    Returns:
        (incident_title, rendered_results, product_name, detection_query, json_preview_path)
    """
    all_rendered: List[str] = []
    json_preview_path: Optional[Path] = None
    detection_query: Optional[str] = None

    for idx, alert in enumerate(alerts, start=1):
        incident_title = alert["IncidentTitle"]
        product_name = alert["ProductName"]
        start_time_utc = alert["StartTimeUTC"]
        end_time_utc = alert["EndTimeUTC"]
        detection_query = alert["Query"]
        alert_id = alert["AlertId"]

        if product_name.lower().endswith("sentinel"):
            logging.info("Running detection query for Alert %d: %s (%s)", idx, incident_title, alert_id)
            timespan = f"{start_time_utc}/{end_time_utc}"
            table = _query_log_analytics(workspace_id=workspace_id, query=detection_query, timespan=timespan, verify_tls=False, tenant_id=tenant_id)
            table = _extract_first_table(table)

            csv_path = Path(f"query_table_alert_{idx}.csv")
            json_path = Path(f"query_table_alert_{idx}.json")
            save_table_to_csv_and_preview_json(table, csv_path, json_path)
            json_preview_path = json_path

            # Open the CSV if we're on Windows (os.startfile)
            if platform.system() == "Windows":
                try:
                    os.startfile(str(csv_path))  # type: ignore
                except Exception:
                    pass

            columns = [c["name"] for c in table["columns"]]
            rows = table["rows"]
            row_count = len(rows)

            if row_count <= 100:
                joined = "<br />".join([",".join(columns)] + [",".join(map(str, r)) for r in rows])
                all_rendered.append(joined)
            else:
                head = rows[:100]
                note = f"<p><strong>Showing first 100 of {row_count} events</strong></p>\n"
                joined = "<br />".join([",".join(columns)] + [",".join(map(str, r)) for r in head])
                all_rendered.append(note + "<pre>" + joined + "</pre>")

        else:
            # Non-Sentinel: fetch alert link(s)
            links_table = _query_log_analytics(workspace_id, alert_link_query, timespan="P7D", verify_tls=False)
            links_table = _extract_first_table(links_table)
            if links_table and links_table.get("rows"):
                for row in links_table["rows"]:
                    link = str(row[0])
                    html_link = f'<p>{escape(product_name)}: <a href="{escape(link)}" target="_blank">{escape(link)}</a></p>'
                    all_rendered.append(html_link)
            else:
                all_rendered.append(f"<p>No alert link found for this alert in {escape(product_name)}</p>")

    # Return from the *first* alert for meta fields
    first = alerts[0]
    return (
        first["IncidentTitle"],
        all_rendered,
        first["ProductName"],
        detection_query,
        json_preview_path,
    )

# ----------------------------------------------------------------------------
# MITRE helpers
# ----------------------------------------------------------------------------
def _strip_code_fences(s: str) -> str:
    fence = re.compile(r"^```(?:json|python|py|yaml|yml)?\s*([\s\S]*?)\s*```$", re.IGNORECASE)
    m = fence.search(s.strip())
    return m.group(1).strip() if m else s.strip()


def _valid_tid(tid: str) -> bool:
    return isinstance(tid, str) and bool(_TID_RE.match(tid.strip()))


def extract_techniques(text: str) -> List[Tuple[str, str]]:
    """
    Extract ATT&CK techniques from LLM output. Supports:
      - JSON array of objects [{"technique_id","reason"}, ...]
      - Single JSON object {"technique_id","reason"}  <-- NEW
      - Dict-of-dicts { "Txxxx": {"technique_id","reason"}, ... }
      - Python list-of-tuples
      - Line-based "T####(.###)? | desc"
    """
    if not isinstance(text, str):
        return []
    s = _strip_code_fences(text)

    def json_to_tuples(obj: Any) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        seen: set[str] = set()

        # NEW: handle single object {"technique_id": "...", "reason": "..."}
        if isinstance(obj, dict) and (
            ("technique_id" in obj or "TechniqueId" in obj or "techniqueId" in obj)
            and ("reason" in obj or "Reason" in obj)
        ):
            tid = obj.get("technique_id") or obj.get("TechniqueId") or obj.get("techniqueId")
            reason = obj.get("reason") or obj.get("Reason") or ""
            if tid and _valid_tid(tid):
                tid = tid.strip()
                pair = (tid, str(reason).strip())
                if tid not in seen:
                    seen.add(tid)
                    out.append(pair)
            return out  # done

        if isinstance(obj, list):
            for item in obj:
                if not isinstance(item, dict):
                    continue
                tid = item.get("technique_id") or item.get("TechniqueId") or item.get("techniqueId")
                reason = item.get("reason") or item.get("Reason") or ""
                if tid and _valid_tid(tid):
                    tid = tid.strip()
                    pair = (tid, str(reason).strip())
                    if tid not in seen:
                        seen.add(tid)
                        out.append(pair)
            return out

        # dict-of-dicts fallback
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, dict):
                    tid = v.get("technique_id") or v.get("TechniqueId") or v.get("techniqueId") or k
                    reason = v.get("reason") or v.get("Reason") or ""
                    if tid and _valid_tid(tid):
                        tid = tid.strip()
                        pair = (tid, str(reason).strip())
                        if tid not in seen:
                            seen.add(tid)
                            out.append(pair)
            return out

        return out

    # 1) Strict JSON first
    try:
        parsed = json.loads(s)
        tuples = json_to_tuples(parsed)
        if tuples:
            return tuples

        # NEW: if top-level is dict but not directly parseable, try coercing to array
        if isinstance(parsed, dict):
            tuples = json_to_tuples([parsed])
            if tuples:
                return tuples
    except Exception:
        pass

    # 1b) First JSON array substring
    for m in re.finditer(r"\[\s*{[\s\S]*?}\s*(?:,\s*{[\s\S]*?}\s*)*\s*\]", s):
        try:
            candidate = json.loads(m.group(0))
            tuples = json_to_tuples(candidate)
            if tuples:
                return tuples
        except Exception:
            continue

    # 2) Python list-of-tuples
    list_match = re.search(r"\[[\s\S]*?\]", s)
    if list_match:
        snippet = list_match.group(0)
        try:
            import ast as _ast  # local import
            parsed = _ast.literal_eval(snippet)
            if isinstance(parsed, list) and all(isinstance(t, tuple) and 1 <= len(t) <= 2 for t in parsed):
                out: List[Tuple[str, str]] = []
                seen: set[str] = set()
                for t in parsed:
                    tid = str(t[0]).strip()
                    reason = str(t[1]).strip() if len(t) > 1 else ""
                    if _valid_tid(tid) and tid not in seen:
                        seen.add(tid)
                        out.append((tid, reason))
                if out:
                    return out
        except Exception:
            pass

    # 3) Line-based
    out: List[Tuple[str, str]] = []
    seen: set[str] = set()
    for ln in (ln.strip() for ln in s.splitlines() if ln.strip()):
        m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", ln)
        if not m:
            continue
        tid = m.group(0)
        if not _valid_tid(tid) or tid in seen:
            continue
        reason = ""
        if "|" in ln:
            _, desc = ln.split("|", 1)
            reason = desc.strip()
        seen.add(tid)
        out.append((tid, reason))
    return out

def normalize_techniques(techniques_llm: Union[str, List[Union[str, Tuple[str, str]]]],
                         techniques: Optional[List[Tuple[str, str]]]) -> List[Tuple[str, str]]:
    """Normalize to a list of (technique_id, reason) tuples and deduplicate by ID."""
    flat: List[Tuple[str, str]] = []

    def _add_pair(tid: str, reason: str = ""):
        tid, reason = tid.strip(), reason.strip()
        if tid:
            flat.append((tid, reason))

    if isinstance(techniques_llm, str):
        for entry in re.split(r"[\n]+", techniques_llm):
            entry = entry.strip()
            if not entry:
                continue
            if "|" in entry:
                tid, reason = entry.split("|", 1)
                _add_pair(tid, reason)
            else:
                _add_pair(entry, "")
    elif isinstance(techniques_llm, list):
        for t in techniques_llm:
            if isinstance(t, tuple):
                if len(t) == 1:
                    _add_pair(str(t[0]), "")
                else:
                    _add_pair(str(t[0]), str(t[1]))
            elif isinstance(t, str):
                for entry in re.split(r"[\n]+", t):
                    entry = entry.strip()
                    if not entry:
                        continue
                    if "|" in entry:
                        tid, reason = entry.split("|", 1)
                        _add_pair(tid, reason)
                    else:
                        _add_pair(entry, "")

    base = techniques[:] if techniques else []
    base.extend(flat)

    # Normalize and deduplicate by technique_id (keep last occurrence)
    norm = []
    seen: Dict[str, int] = {}
    for pair in base:
        tid, reason = (pair if isinstance(pair, tuple) else (str(pair), ""))
        tid = tid.strip()
        reason = (reason or "").strip()
        if not tid:
            continue
        # update index if seen
        if tid in seen:
            norm[seen[tid]] = (tid, reason)
        else:
            seen[tid] = len(norm)
            norm.append((tid, reason))
    return norm

# ----------------------------------------------------------------------------
# HTML output
# ----------------------------------------------------------------------------
def generate_html_report(
    incident_no: Union[int, str],
    incident_title: str,
    query_result_rendered: Union[str, List[str]],
    ABIPDB_analysis: str,
    skipped_ip_analysis: str,
    domain_analysis: str,
    file_hash_analysis: str,
    mitre_attack_map: str,
) -> str:
    """Assemble final HTML report."""

    if all(not (x or "").strip() for x in [ABIPDB_analysis, skipped_ip_analysis, domain_analysis, file_hash_analysis]):
        osint_checks_html = "<p>N/A</p>"
    else:
        osint_checks_html = f"{ABIPDB_analysis}{skipped_ip_analysis}{domain_analysis}{file_hash_analysis}"

    # Normalize query result into HTML
    if isinstance(query_result_rendered, list):
        # If items already contain <p> links, join as-is; else wrap in <pre>
        if any("<p>" in str(item) for item in query_result_rendered):
            qr_html = "".join(str(item) for item in query_result_rendered if str(item).strip())
        else:
            qr_html = "<pre>" + "<br /><br />".join(str(q) for q in query_result_rendered if str(q).strip()) + "</pre>"
    else:
        s = str(query_result_rendered)
        if "<p>" in s and "<br />" not in s:
            qr_html = s
        else:
            qr_html = "<pre>" + s + "</pre>"

    html_content = f"""
    <h1>Incident: {escape(str(incident_no))} - {escape(incident_title)}</h1>
    <h2>Events</h2>
    {qr_html}
    <h2>OSINT Checks</h2>
    {osint_checks_html}
    {mitre_attack_map}
    <h2>Investigation Notes</h2>
    <p>&nbsp;</p>
    <h2>Conclusion</h2>
    <p>&nbsp;</p>
    <h2>Next Course of Action</h2>
    <p>&nbsp;</p>
    """
    return html_content


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------
def main_menu() -> str:
    while True:
        beep()
        print("\nMain Menu:")
        print("1. Use Azure Monitor Logs to obtain the detection query results")
        print("2. Use a CSV file or paste event details manually")
        print("3. Exit")
        choice = input("Enter your choice (1/2/3): ").strip()
        if choice in {"1", "2", "3"}:
            return choice
        logging.error("Invalid selection. Please enter 1, 2, or 3.")


def get_query_results_from_file() -> Tuple[str, Path]:
    """Prompt user to select a CSV, return rendered HTML text and preview JSON path."""
    print("Please select a CSV file containing the query results.")

    csv_path = select_csv_via_gui()
    if not csv_path:
        print("No file selected. Exiting.")
        sys.exit(1)

    # raw text for HTML view
    raw = csv_path.read_text(encoding="utf-8-sig").replace("\n", "<br />")

    # preview JSON path
    preview_json = Path("query_result.json")
    try:
        df = pd.read_csv(csv_path)
        df.head().to_json(preview_json, orient="records", indent=2, force_ascii=False)
    except Exception as e:
        logging.warning("Failed to generate JSON preview from CSV: %s", e)

    return raw, preview_json


def run() -> None:
    setup_logging(verbose=True)

    start_time = time.perf_counter()
    osint_needed = False

    print("\nWelcome to the Alert Documentation Tool!")
    print("This tool will generate an HTML report from detection query results.")
    choice = main_menu()

    # Load query config (YAML recommended)
    cfg = load_config("config.yaml")

    if choice == "1":
        # Azure Monitor Logs path
        if platform.system() == "Windows":
            close_excel_with_file_open("query_table")

        print("\nYou selected Azure Monitor Logs.")
        tenant_id = input("Enter the Azure Tenant ID (as a GUID) or domain (or press Enter): ").strip()
        if tenant_id and validate_tenant_id(tenant_id):
            workspace_id, tenant_id = azure_monitor_login(tenant_id=tenant_id)
        elif tenant_id == "":
            if prompt_yes_no("Would you like to login to Azure to retrieve the Workspace ID for the tenant?"):
                workspace_id, tenant_id = azure_monitor_login(tenant_id=tenant_id)
        else:
            # loop until valid manual entry
            while True:
                tenant_id = input("Please enter the Tenant ID: ").strip()
                if validate_tenant_id(tenant_id):
                    workspace_id, tenant_id = azure_monitor_login(tenant_id=tenant_id)
                    break
                logging.error("Invalid Tenant ID format. Try again.")
        logging.info("Using Tenant ID: %s", tenant_id)

        incident_no = get_valid_incident_id()

        print(f"Retrieving detection details for Incident ID: {incident_no}")
        q = cfg["incident_details_query"].format(incident_no=incident_no)
        result = _query_log_analytics(workspace_id=workspace_id, query=q, timespan="P1D", verify_tls=False, tenant_id=tenant_id)

        def _has_rows(res: Dict[str, Any]) -> bool:
            return bool(res) and any(t.get("rows") for t in res.get("tables", []))

        if not _has_rows(result):
            logging.info("No results for 1 day. Trying 7 days...")
            result = _query_log_analytics(workspace_id=workspace_id, query=q, timespan="P7D", verify_tls=False, tenant_id=tenant_id)
            if not _has_rows(result):
                print("No results for 7 days. Exiting.")
                sys.exit(0)

        table = _extract_first_table(result)
        alerts, first_alert_id = prepare_results(table)

        link_query = cfg["get_alert_link_query"].format(alert_id=first_alert_id)
        incident_title, rendered, product_name, detection_query, json_preview = run_detection_queries_on_alerts(
            alerts=alerts, workspace_id=workspace_id, alert_link_query=link_query, tenant_id=tenant_id
        )

        # If alert is from Sentinel, we'll offer MITRE + OSINT on those events
        if product_name.lower().endswith("sentinel"):
            osint_needed = True

            # Build MITRE prompt (use CSV preview JSON for events)
            events_for_llm: Union[Path, str, List[Dict[str, Any]]]
            if json_preview and json_preview.exists():
                try:
                    events_for_llm = json.loads(json_preview.read_text(encoding="utf-8"))
                except Exception:
                    events_for_llm = []
            else:
                events_for_llm = []

            tmpl = Template(cfg["PROMPT_TEMPLATE_FOR_MITRE_ATTACK_TECHNIQUES"])
            prompt = tmpl.substitute(
                MITRE_VERSION=MITRE_VERSION,
                ALERT_DETAILS=f"KQL:\n{detection_query}\n\nEvents:\n{events_for_llm}",
                ALERT_TITLE=incident_title,
            )

        else:
            osint_needed = False
            prompt = ""  # no MITRE prompt if not Sentinel

    elif choice == "2":
        # CSV or text path
        if prompt_yes_no("Use a CSV file (Yes) or paste text (No)?"):
            query_result, preview_json_path = get_query_results_from_file()
            try:
                events_for_llm = json.loads(preview_json_path.read_text(encoding="utf-8"))
            except Exception:
                events_for_llm = []
        else:
            print("Paste the incident details below (end with an empty line):")
            buf = []
            while True:
                line = input()
                if not line.strip():
                    break
                buf.append(line)
            query_result = "<br />".join(buf).strip()
            events_for_llm = query_result  # no structured JSON
        incident_no = input("Incident Number: ").strip()
        incident_title = input("Incident Title: ").strip()
        osint_needed = True  # permitted against pasted/CSV content

        tmpl = Template(cfg["PROMPT_TEMPLATE_FOR_MITRE_ATTACK_TECHNIQUES"])
        prompt = tmpl.substitute(
            MITRE_VERSION=MITRE_VERSION,
            ALERT_DETAILS=f"Events:\n{events_for_llm}",
            ALERT_TITLE=incident_title,
        )

        rendered = query_result  # already normalized for this branch

    else:
        print("Exiting. Goodbye!")
        sys.exit(0)

    # --- MITRE ATT&CK mapping (optional) ---
    mitre_attack_map = ""
    if prompt and prompt_yes_no("Perform MITRE ATT&CK mapping for this alert?"):
        print("\nAttempting to find ATT&CK techniques using a local LLaMA3 (Ollama).")
        print("====================\nPrompt sent to Ollama:\n====================")
        print(prompt)
        print("====================\n")

        #load ollama api key
        cfg = load_config("config.json")  # load config with API keys
        ollama_api_key = cfg["ollama_api_key"]
        mitre_output = run_ollama(prompt, ollama_api_key=ollama_api_key, ollama_model="gpt-oss:120b")
        if mitre_output != "s":
            print("====================\nRaw output from Ollama:\n====================")
            print(mitre_output)
            print("====================\n")
            techniques_llm = extract_techniques(mitre_output)
            techniques_norm = normalize_techniques(techniques_llm, None)    
            logging.info("MITRE techniques parsed: %s", techniques_norm)
            mitre_attack_map = mitre_attack_html_section(techniques_norm, MITRE_VERSION)
        else:
            logging.info("MITRE mapping skipped by user.")

    # --- OSINT checks (optional) ---
    if osint_needed:
        print("\nPlease review the generated CSV/Excel first.")
        do_osint = prompt_yes_no("Run OSINT checks on the indicators in this data?")
        if do_osint:
            logging.info("Starting OSINT checks...")
            if _HAS_NEST_ASYNCIO:
                try:
                    nest_asyncio.apply()  # type: ignore
                except Exception:
                    pass
            cfg = load_config("config.json")  # load config with API keys
            ABIPDB, SKIP, DOM, HASH = osint_check(rendered, cfg)
        else:
            ABIPDB = SKIP = DOM = HASH = ""
    else:
        ABIPDB = SKIP = DOM = HASH = ""

    # --- Build and show HTML report ---
    html = generate_html_report(
        incident_no=incident_no,
        incident_title=incident_title,
        query_result_rendered=rendered,
        ABIPDB_analysis=ABIPDB,
        skipped_ip_analysis=SKIP,
        domain_analysis=DOM,
        file_hash_analysis=HASH,
        mitre_attack_map=mitre_attack_map,
    )

    REPORT_HTML.write_text(html, encoding="utf-8")
    print(f"\nHTML report created: {REPORT_HTML}")
    try:
        import webbrowser
        webbrowser.open(str(REPORT_HTML))
    except Exception:
        pass

    elapsed = time.perf_counter() - start_time
    beep()
    print(f"⏱ Execution time: {format_elapsed(elapsed)}\n")

    if choice == "1":
        print(
            "\nTo complete the investigation, you can use the CLI in the repo:\n"
            "  UAB_workbook_runner_cli.py  (Azure-Sentinel-Workbooks)\n"
            "This tool runs queries from User_Analytics_Behaviour.json against a Log Analytics workspace.\n\n"
            "Repo: https://github.com/MYoussef23/Azure-Sentinel-Workbooks\n\n"
            "Prereqs:\n"
            "  • AZ CLI installed and logged in (e.g., `az account show` works)\n"
            "  • `pip install fire requests`\n\n"
            "Examples:\n"
            "  # List queries (index + title)\n"
            "  python UAB_workbook_runner_cli.py list --workbook_path User_Analytics_Behaviour.json\n\n"
            "  # Run a query by index for the last 1 day (P1D) with a placeholder value\n"
            "  python UAB_workbook_runner_cli.py run 7 <workspace_id_guid> P1D "
            "--UserPrincipalName <UPN> --limit 50\n\n"
            "  # Run and export all results to JSON\n"
            "  python UAB_workbook_runner_cli.py run 12 <workspace_id_guid> P7D "
            "--UserPrincipalName <UPN> --output json --outfile results.json\n\n"
            "  # Save the rendered KQL to a .kql file (for review/sharing)\n"
            "  python UAB_workbook_runner_cli.py run 3 <workspace_id_guid> P3D --save_rendered_kql True\n"
        )

def main() -> None:
    try:
        run()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except Exception as e:
        beep()
        logging.exception("Execution error: %s", e)


if __name__ == "__main__":
    main()
