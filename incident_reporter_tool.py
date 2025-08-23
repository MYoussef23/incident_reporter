import os
import time
from html import escape
import json
import yaml
import re
import ast
import azure_monitor_get_workspace
import azure_monitor_logs_run_query
import iocextract
import osint_scanner
import get_mitre_attack_details
import ollama_prompt
import investigation_query_pack
import beep
from typing import List, Tuple
from pathlib import Path
import webbrowser 
import nest_asyncio
import warnings
from urllib3.exceptions import InsecureRequestWarning
from tkinter import Tk, filedialog
import pandas as pd
import win32com.client

warnings.simplefilter('ignore', InsecureRequestWarning)

def close_excel_with_file_open(filename):
    try:
        excel = win32com.client.GetActiveObject("Excel.Application")
        # Copy list of workbooks to avoid iterator issues
        workbooks = [wb for wb in excel.Workbooks]
        closed_any = False
        for wb in workbooks:
            #if filename.lower() in wb.FullName.lower():
            if '.csv' in wb.FullName.lower() and filename.lower() in wb.FullName.lower():
                fullname = wb.FullName  # Save before closing for print
                wb.Close(SaveChanges=False)
                print(f"Closed: {fullname}")
                closed_any = True
        if closed_any and excel.Workbooks.Count == 0:
            excel.Quit()
    except Exception as e:
        if hasattr(e, 'hresult') and e.hresult == -2147221021:
            print("Excel is not running, nothing to close.")
            return
        print("Could not close Excel file:", e)

def get_valid_incident_id():
    while True:
        incident_id = get_incident_number()
        beep.beep()     # Play a notification sound for user attention
        user_continue = input(f"\nYou have selected Incident ID: {incident_id}. Do you want to continue? (Y/N): ").strip().lower()
        if user_continue in ['y', 'yes']:
            return incident_id  # Proceed with this incident ID
        elif user_continue in ['n', 'no']:
            print("Let's enter a different Incident ID.")
            continue
        else:
            beep.beep()     # Play a notification sound for user attention
            print("Invalid input. Please enter 'Y' to continue or 'N' to re-enter the Incident ID.")

def get_incident_number():      # This will loop till the user enters a valid entry which is a positive integer (Sentinel works off positive integer incident number types)
    while True:
            beep.beep()     # Play a notification sound for user attention
            incident_id = input("Enter the Incident ID: ").strip()
            try:
                if incident_id.isdigit():
                    incident_id = int(incident_id)
                    if incident_id > 0:
                        return incident_id
                else:
                    beep.beep()     # Play a notification sound for user attention
                    print("❌ Invalid input. Please enter a valid incident number, which for Sentinel is a numeric value.")
            except ValueError:
                beep.beep()     # Play a notification sound for user attention
                print("❌ Invalid input. Please enter a valid incident number, which for Sentinel is a numeric value.")

def save_to_csv(table, filename_csv, filename_json):
    # put table data in dataframe
    df = pd.DataFrame(table["rows"], columns=[col["name"] for col in table["columns"]])
    # Save dataframe as CSV
    df.to_csv(filename_csv, index=False)
    # Save only the first 5 rows of the dataframe as JSON
    df.head().to_json(filename_json, orient="records", indent=2)


#===================================================Query Results From File===================================================#
    
def get_query_results_from_file():
    # Get the query result from file
        # Prompt the user to select a CSV file
    print("Please select a CSV file containing the query results.")
    Tk().withdraw()  # Hide the root window
    csv_file_path = filedialog.askopenfilename(
        title="Select CSV File",
        filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
    )

    if not csv_file_path:
        print("No file selected. Exiting.")
        exit(1)

    # Read the CSV file contents as the query result
    with open(csv_file_path, "r", encoding="utf-8-sig") as f:
        # Convert the dataframe to HTML format in plain text format
        query_result = f.read().replace('\n', '<br />')
    
    # Convert the CSV data to a JSON object
    query_result_data = pd.read_csv(csv_file_path).head().to_dict(orient='records')
    # Save json data to file
    # Save the JSON data to a file
    json_query_results = "query_result.json"
    if os.path.exists(json_query_results):
        os.remove(json_query_results)
    with open("query_result.json", "w", encoding="utf-8") as json_file:
        json.dump(query_result_data, json_file, indent=2)
    
    return query_result, json_query_results

# ------------ Load Configuration File ------------ #

# Function to load the configuration from a JSON file
def load_config(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    _, ext = os.path.splitext(file_path)
    ext = ext.lower()

    with open(file_path, "r") as f:
        data = f.read()
        if ext in [".yaml", ".yml"]:
            if yaml is None:
                raise ImportError("PyYAML is not installed. Please install it with 'pip install pyyaml'.")
            try:
                config = yaml.safe_load(data)
                return config
            except yaml.YAMLError as e:
                raise ValueError(f"Error parsing the YAML configuration file: {e}")
        elif ext == ".json":
            try:
                config = json.loads(data)
                return config
            except json.JSONDecodeError as e:
                raise ValueError(f"Error parsing the JSON configuration file: {e}")
        else:
            raise ValueError(f"Unsupported configuration file format: {ext}")

# ------------ IOC Extraction ------------ #

def extract_iocs_in_data(csv_data):     # Extract all relevant IOC's from the query result
    iocs = {
        "ips": set(),
        "domains": set(),
        "hashes": set()
        }

    def process_single_csv(single_csv):
        # Normalize line breaks and parse as text
        cleaned = single_csv.replace("<br />", ",")
        # iocextract finds IOCs in arbitrary text—no need to tokenize by commas
        iocs["ips"].update(
            ip for ip in iocextract.extract_ips(cleaned)
            if osint_scanner.validate_IP(ip)  # Only keep IPs passing your check
        )

        # Extract domains
        domain_regex = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        all_domains = re.findall(domain_regex, cleaned)
        # Remove those that are actually IPs
        domains = [d for d in all_domains if not re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', d)]

        for d in set(domains):
            if osint_scanner.validate_domain(d):
                iocs["domains"].add(d)

        iocs["hashes"].update(iocextract.extract_hashes(cleaned))   # Extract hashes

    # Check if csv_data is a list or a single string
    if isinstance(csv_data, list):
        for single_csv in csv_data:
            process_single_csv(single_csv)
    elif isinstance(csv_data, str):
        process_single_csv(csv_data)
    else:
        raise TypeError("csv_data must be a string or a list of strings.")

    return {k: list(v) for k, v in iocs.items()}

# ------------OSINT Check------------ #
def OSINT_check(query_result):
    # Initialise variables for OSINT checks
    ABIPDB_analysis = ""
    skipped_ip_analysis = ""
    domain_analysis = ""
    hash_analysis = ""
    org_cidrs = None        # Initialise org_cidrs to None for AbuseIPDB/VT domain checks

    # Load configuration
    config = load_config('config.json')  # Load the configuration file
    VT_api_key = config["VT_api_key"]
    ABDB_api_key = config["ABDB_api_key"]

    print("🔍 Beginning IOC extraction from data...")
    iocs = extract_iocs_in_data(query_result)
    
    # set the entity lists
    ip_list = []
    domain_list = []
    file_hash_list = []
        # Add IOC's to respective lists
    ip_list += iocs.get("ips", [])
    domain_list += iocs.get("domains", [])
    file_hash_list += iocs.get("hashes", [])

    # Perform OSINT checks based on the entity type -------------------------------------

        # IP addresses - AbuseIPDB
    if ip_list:# Perform OSINT checks for IP addresses in AbuseIPDB
        print(f"\nPerforming OSINT checks for IP addresses.")
        # Complete IP analysis - AbuseIPDB
        header, rows, org_cidrs, skipped_ips_by_cidr = osint_scanner.loop_abuseIP_check(ABDB_api_key, ip_list)
        if header and rows:
            ABIPDB_analysis = (
                "<p><a href=https://www.abuseipdb.com/>https://www.abuseipdb.com/</a> IP Analysis:</p>"
                + "<table border='1'>" +
                    "<tr>" + "".join(f"<th>{col}</th>" for col in header) + "</tr>" +
                    "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows) +
                "</table>"
            )
            # Prepare skipped report
            if skipped_ips_by_cidr:
                if len(skipped_ips_by_cidr) > 1:
                    # Add the explanatory line before the bullet list
                    skipped_ip_analysis = (
                        "<p>The following IPs were not individually checked as they belong to the already-analysed network ranges:</p>"
                        "<ul>"
                    )
                    for cidr, ips in skipped_ips_by_cidr.items():
                        ip_str = ", ".join(ips)
                        skipped_ip_analysis += f"<li><strong>{cidr}:</strong> {ip_str}</li>"
                    skipped_ip_analysis += "</ul>"
                else:
                    # Only one CIDR: Just use a single line, no bullets
                    cidr, ips = next(iter(skipped_ips_by_cidr.items()))
                    ip_str = ", ".join(ips)
                    skipped_ip_analysis = (
                        f"<p>The following IPs were not individually checked as they belong to the already-analysed network range <strong>{cidr}</strong>: {ip_str}.</p>"
                    )
            else:
                skipped_ip_analysis = ""

        # Domain Analysis - VirusTotal
    if domain_list:
        # Perform OSINT checks for URLs in VirusTotal
        print(f"\nPerforming OSINT checks for domains.")
        # Complete domain Analysis - VirusTotal
        if org_cidrs is None:
            header, rows = osint_scanner.loop_domain_vt_check(VT_api_key, domain_list)
        else:
            header, rows = osint_scanner.loop_domain_vt_check(VT_api_key, domain_list, org_cidrs=org_cidrs)
        if header and rows:
            # separate the header and rows with a comma
            domain_analysis = (
                "<p><a href=https://www.virustotal.com/>https://www.virustotal.com/</a> Domain Analysis:</p>"
                + "<table border='1'>" +
                    "<tr>" + "".join(f"<th>{col}</th>" for col in header) + "</tr>" +
                    "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows) +
                "</table>"
            )
        else:
            print("No external domains to check.")

        # File hash - VirusTotal
    if file_hash_list:
        # Perform OSINT checks for file paths in VirusTotal
        print(f"\nPerforming OSINT checks for file hashes: {file_hash_list}")
        # Complete file hash analysis - VirusTotal
        header, rows = osint_scanner.loop_file_hash_vt_check(VT_api_key, file_hash_list)
        if header and rows:
            # separate the header and rows with a comma
            hash_analysis = (
                "<p><a href=https://www.virustotal.com/>https://www.virustotal.com/</a> File Hash Analysis:</p>"
                + "<table border='1'>" +
                    "<tr>" + "".join(f"<th>{col}</th>" for col in header) + "</tr>" +
                    "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows) +
                "</table>"
            )

    return ABIPDB_analysis, skipped_ip_analysis, domain_analysis, hash_analysis

def prepare_results(result):  # Ensure result is in the expected format
    # Extract and return fields
    alerts = []
    for row in result["rows"]:
        incident_title, product_name, alert_id, start_time_utc, end_time_utc, query, tactics, techniques  = row

        print(f"Alert Title: {incident_title}")
        print(f"Product Name: {product_name}")
        print(f"Alert ID: {alert_id}")
        print(f"Start Time (UTC): {start_time_utc}")
        print(f"End Time (UTC): {end_time_utc}")
        print(f"Query: {query}")
        print(f"Tactics: {tactics}")
        print(f"Techniques: {techniques}")

        # Collect for further use
        alerts.append({
            "IncidentTitle": incident_title,
            "ProductName": product_name,
            "AlertId": alert_id,
            "StartTimeUTC": start_time_utc,
            "EndTimeUTC": end_time_utc,
            "Query": query,
            "Tactics": tactics,
            "Techniques": techniques
        })

    return alerts, alerts[0]['AlertId']  # Return the list of alerts for further processing

def run_detection_queries_on_alerts(alerts, workspace_id, alert_link_query):  # Run detection queries on the alerts
    all_query_results = []

    for idx, alert in enumerate(alerts, start=1):
        incident_title = alert["IncidentTitle"]
        product_name = alert["ProductName"]
        start_time_utc = alert["StartTimeUTC"]
        end_time_utc = alert["EndTimeUTC"]
        detection_query = alert["Query"]
        alert_id = alert["AlertId"]
        tactics = alert["Tactics"]
        techniques = alert["Techniques"]

        if product_name.lower().endswith("sentinel"):    # If the product name ends with "Sentinel", run the detection query
            print(f"\nRunning detection query for Alert {idx}: {incident_title} ({alert_id})")
            timespan = f"{start_time_utc}/{end_time_utc}"
            query_table = azure_monitor_logs_run_query.run_query(workspace_id, detection_query, timespan)

            # Export results to CSV (unique file for each alert)
            csv_filename = f"query_table_alert_{idx}.csv"
            json_filename = f"query_table_alert_{idx}.json"
            save_to_csv(query_table, csv_filename, json_filename)
            print(f"\nQuery result saved to {csv_filename}")

            # Open the file in default CSV viewer
            print(f"Opening query result file: {csv_filename}...")
            os.startfile(csv_filename)

            # Get number of rows in the query_table
            row_count = len(query_table["rows"])

            # Normalise query_result into HTML format
            columns = [col["name"] for col in query_table["columns"]]

            if row_count < 100:     # If row count is less that 100, then normalise data in HTML format
                rows = query_table["rows"]
                note_html = ""
                query_result = note_html + "<br />".join(
                        [",".join(columns)] +
                        [",".join(str(cell) for cell in row) for row in rows]
                    )
            else:   # Provide a CSV download link if more than 100 rows
                print(f"⚠ Events exceed 100 rows ({row_count} rows). Displaying first 100 rows only in HTML output...")
                rows = query_table["rows"][:100]
                note_html = f"<p><strong>Showing first 100 of {row_count} events</strong></p>\n"
                query_result = note_html + "<pre>" + "<br />".join(
                        [",".join(columns)] +
                        [",".join(str(cell) for cell in row) for row in rows]
                    ) + "</pre>"
            
            all_query_results.append(query_result)

        else:   # Get the alert link
            alert_links = azure_monitor_logs_run_query.run_query(workspace_id, alert_link_query, timespan="P7D")
            # Extract the actual link(s) from the query result
            if alert_links and "rows" in alert_links and alert_links["rows"]:
                # Support for multiple links, though usually just one per alert
                for row in alert_links["rows"]:
                    alert_link = row[0]
                    print(f"\nAlert Link for Alert {idx} ({product_name}): {incident_title} ({alert_id}\n{alert_link}")

                    # format as HTML hyperlink
                    html_link = f'<p>{product_name}: <a href="{alert_link}" target="_blank">{alert_link}</a></p>'
                    all_query_results.append(html_link)
            else:
                print(f"No alert link found for Alert {idx} ({product_name}): {incident_title} ({alert_id})")
                all_query_results.append(f"<p>No alert link found for this alert in {product_name}</p>")
    
    return alerts[0]["IncidentTitle"], all_query_results, tactics, techniques, product_name, detection_query, json_filename

def prompt_for_mitre_attack_techniques(prompt, incident_title, techniques=None):
    # Ask the user if they wish to proceed
    user_choice = input("⚠️ Do you want to perform MITRE ATT&CK mapping for this alert? (y/n): ").strip().lower()

    # Keep asking until valid input is given
    while True:
        if user_choice in ("y", "yes"):
            #  make sure techniques is a list
            if isinstance(techniques, str):
                # If techniques is a string representation of a list, use ast.literal_eval
                try:
                    techniques = ast.literal_eval(techniques)
                except Exception:
                    techniques = [t.strip() for t in techniques.split(",") if t.strip()]
            
            # Try to find techniques related to the alert using LLM prompt
            print(f"\nAttempting to find MITRE ATT&CK techniques related to the alert: {incident_title}, using a local LLaMA3 LLM. This may take a minute on first run while the model loads...")
            # --- Show the prompt being sent ---
            print("\n====================")
            print("📤 Prompt sent to Ollama:")
            print("====================")
            print(prompt)
            print("====================\n")

            # Prompt the LLM to find techniques related to the alert
            mitre_output = ollama_prompt.run_ollama(prompt)
            if mitre_output == "s":
                mitre_attack_map = ""
                break

            # --- Show raw output from Ollama ---
            print("\n====================")
            print("📥 Raw output from Ollama:")
            print("====================")
            print(mitre_output)
            print("====================\n")

            # Extract techniques from LLM output
            techniques_llm = extract_techniques(mitre_output)
            # --- Show parsed techniques ---
            print("\n====================")
            print("✅ Parsed MITRE ATT&CK Techniques")
            print("====================")
            # Inspect what you actually have
            print(f"type={type(techniques_llm)} len={len(techniques_llm)}")
            print(techniques_llm)
            print("====================\n")

            techniques = normalize_techniques(techniques_llm, techniques)

            # Complete the MITRE ATT&CK mapping and HTML output
            print(f"\nPerforming MITRE ATT&CK mapping for techniques: {techniques}")
            mitre_attack_map = get_mitre_attack_details.mitre_attack_html_section(techniques)
        
        elif user_choice in ("n", "no"):
            print("❌ MITRE ATT&CK mapping skipped by user choice.")
            mitre_attack_map = ""
            break

        else:
            print("❌ Invalid input. Please enter 'y' or 'n'.")

    #return techniques
    return mitre_attack_map

_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

def _strip_code_fences(s: str) -> str:
    # Remove one full fenced block if the whole string is wrapped in it
    fence = re.compile(r"^```(?:json|python|py|yaml|yml)?\s*([\s\S]*?)\s*```$", re.IGNORECASE)
    m = fence.search(s.strip())
    return m.group(1).strip() if m else s.strip()

def _valid_tid(tid: str) -> bool:
    return isinstance(tid, str) and bool(_TID_RE.match(tid.strip()))

def extract_techniques(text: str) -> List[Tuple[str, str]]:
    """
    Extract ATT&CK techniques from LLM output.

    Supports (in order of preference):
      1) Strict JSON array of objects:
         [
           {"technique_id": "T1059.001", "reason": "..."},
           {"technique_id": "T1059", "reason": "..."}
         ]
      2) Python list of tuples (legacy):
         [('T1059.001', '...'), ('T1059', '...')]
      3) Line-based:
         T1059.001 | reason text
         T1059

    Returns:
      List[ (TechniqueID, Reason) ] with TechniqueID like T#### or T####.###.
    """
    if not isinstance(text, str):
        return []

    s = _strip_code_fences(text)

    # ---------- 1) Try full-string JSON first ----------
    def json_to_tuples(obj) -> List[Tuple[str, str]]:
        out = []
        seen = set()
        if isinstance(obj, list):
            for item in obj:
                if not isinstance(item, dict):
                    continue
                # Be tolerant of key casing
                tid = item.get("technique_id") or item.get("TechniqueId") or item.get("techniqueId")
                reason = item.get("reason") or item.get("Reason") or ""
                if tid and _valid_tid(tid):
                    pair = (tid.strip(), str(reason).strip())
                    if pair[0] not in seen:
                        seen.add(pair[0])
                        out.append(pair)
        return out
    
    try:
        parsed = json.loads(s)
        tuples = json_to_tuples(parsed)
        if tuples:
            return tuples
        # If it was valid JSON but not the shape we want, continue to other strategies
    except Exception:
        pass

    # ---------- 1b) Try to find the first JSON array substring with objects ----------
    # This pattern finds something that looks like: [ { ... }, { ... }, ... ]
    for m in re.finditer(r"\[\s*{[\s\S]*?}\s*(?:,\s*{[\s\S]*?}\s*)*\s*\]", s):
        try:
            candidate = json.loads(m.group(0))
            tuples = json_to_tuples(candidate)
            if tuples:
                return tuples
        except Exception:
            continue

    # ---------- 2) Legacy: Python list-of-tuples anywhere in the text ----------
    list_match = re.search(r"\[[\s\S]*?\]", s)  # non-greedy
    if list_match:
        snippet = list_match.group(0)
        try:
            parsed = ast.literal_eval(snippet)
            if isinstance(parsed, list) and all(isinstance(t, tuple) and 1 <= len(t) <= 2 for t in parsed):
                out: List[Tuple[str, str]] = []
                seen = set()
                for t in parsed:
                    tid = str(t[0]).strip()
                    reason = str(t[1]).strip() if len(t) > 1 else ""
                    if _valid_tid(tid) and tid not in seen:
                        seen.add(tid)
                        out.append((tid, reason))
                if out:
                    return out
        except Exception:
            pass  # fall through

    # ---------- 3) Fallback: line-based "T####(.###)? | desc" or just "T####(.###)?" ----------
    out: List[Tuple[str, str]] = []
    seen = set()
    for ln in (ln.strip() for ln in s.splitlines() if ln.strip()):
        # find first technique ID in the line
        m = re.search(r"\bT\d{4}(?:\.\d{3})?\b", ln)
        if not m:
            continue
        tid = m.group(0)
        if not _valid_tid(tid) or tid in seen:
            continue
        if "|" in ln:
            # split only on first pipe
            _, desc = ln.split("|", 1)
            reason = desc.strip()
        else:
            reason = ""
        seen.add(tid)
        out.append((tid, reason))

    return out

def normalize_techniques(techniques_llm, techniques):
    """
    Normalize MITRE ATT&CK techniques from an LLM output into a list of (id, desc) tuples.
    Supports input as string, list of strings, or list of tuples.
    
    Args:
        techniques_llm (str | list): Raw techniques data from LLM.
        techniques (list): Existing list of techniques to extend.
    
    Returns:
        list: Normalized list of (id, desc) tuples.
    """
    if isinstance(techniques_llm, str):
        # Split string into tuples (id, desc)
        techniques_llm = [
            tuple(map(str.strip, entry.split("|", 1)))
            for entry in re.split(r'[\n]+', techniques_llm)
            if entry.strip()
        ]

    elif isinstance(techniques_llm, list):
        flat_techniques_llm = []
        for t in techniques_llm:
            if isinstance(t, tuple):
                # Already in (id, desc) form
                flat_techniques_llm.append((t[0].strip(), t[1].strip() if len(t) > 1 else ""))
            elif isinstance(t, str):
                # Split string into entries
                for entry in re.split(r'[\n]+', t):
                    if entry.strip():
                        parts = entry.split("|", 1)
                        flat_techniques_llm.append(
                            (parts[0].strip(), parts[1].strip() if len(parts) > 1 else "")
                        )
        techniques_llm = flat_techniques_llm

    # Extend techniques with new data
    if techniques:
        if techniques_llm:
            techniques.extend(techniques_llm)
    else:
        techniques = techniques_llm

    # Ensure consistent (id, desc) format
    techniques = [
        (t[0], t[1] if len(t) == 2 and t[1].strip() else "")
        if isinstance(t, tuple) else (t, "")
        for t in techniques
    ]

    # Deduplicate by first element of tuple (technique ID), keeping the last occurrence
    return list({t[0]: t for t in techniques}.values())

# ------------ HTML Output Functions ------------ #
def generate_html_report(Incident_no, Incident_title, query_result, ABIPDB_analysis, skipped_ip_analysis, domain_analysis, file_hash_analysis, mitre_attack_map):

    # If all OSINT check results are blank, set output to N/A
    if all(not x.strip() for x in [ABIPDB_analysis, skipped_ip_analysis, domain_analysis, file_hash_analysis]):
        osint_checks = "<p>N/A</p>"
    else:
        osint_checks = f"{ABIPDB_analysis}{skipped_ip_analysis}{domain_analysis}{file_hash_analysis}"
    
    # If query_result is a list (where multiple detection queries was run), join its items; if not, just use it directly
    if isinstance(query_result, list) and all("<p>" not in str(item) for item in query_result):
        # Add a separator or header for clarity if desired:
        qr_string = "<pre>" + "<br /><br />".join(str(q) for q in query_result if str(q).strip()) + "</pre>"
    elif isinstance(query_result, list) and any("<p>" in str(item) for item in query_result):
        # If query_result is a list with HTML links, join them as they are as they already have <p> tags
        qr_string = "".join(str(item) for item in query_result if str(item).strip())
    elif "<br />" in str(query_result): # If query_result is a table
        qr_string = "<pre>" + str(query_result) + "</pre>"
    elif "<p>" in str(query_result):   # if query_table is an alert link
        qr_string = str(query_result)

    html_content = html_content = f"""<h1>Incident: {Incident_no} - {Incident_title}</h1>
    <h2>Events</h2>
    {qr_string}
    <h2>OSINT Checks</h2>
    {osint_checks}{mitre_attack_map}
    <h2>Investigation Notes</h2>
    <p>&nbsp;</p>
    <h2>Conclusion</h2>
    <p>&nbsp;</p>
    <h2>Next Course of Action</h2>
    <p>&nbsp;</p>
    """
    
    return html_content

# ------------ Run Script ------------ #
def main_menu():
    while True:
        beep.beep()     # Play a notification sound for user attention
        print("\nMain Menu:")
        print("1. Use Azure Monitor Logs to obtain the detection query results")
        print("2. Use a CSV file containing the query results or enter event details manually (you will be prompted if you wish to select a CSV file or enter the event details manually using text input)")
        print("3. Exit the tool")
        choice = input("Enter your choice (1/2/3): ").strip()
        
        if choice == '1':
            # Handle Azure Monitor Logs
            beep.beep()     # Play a notification sound for user attention
            user_selection = input("You have selected to use Azure Monitor Logs. Do you wish to continue? (Y/N)\n " \
                                    "Enter 'Y' to continue or 'N' to return to the main menu: ").strip().lower()
            while user_selection not in ['yes', 'y', 'no', 'n']:
                beep.beep()     # Play a notification sound for user attention
                user_selection = input("Invalid selection. Please enter 'yes' or 'no': ").strip().lower()
            if user_selection in ['no', 'n']:
                print("Returning to the main menu...")
                continue
            else:
                return '1'  # Return to indicate Azure Monitor Logs selection
        elif choice == '2':
            # Handle CSV file input
            beep.beep()     # Play a notification sound for user attention
            user_selection = input("You have selected to use a CSV file containing the query results. Do you wish to continue? (Y/N)\n " \
                                    "Enter 'Y' to continue or 'N' to return to the main menu: ").strip().lower()
            while user_selection not in ['yes', 'y', 'no', 'n']:
                beep.beep()     # Play a notification sound for user attention
                user_selection = input("Invalid selection. Please enter 'Y' or 'N': ").strip().lower()
            if user_selection in ['no', 'n']:
                print("Returning to the main menu...")
                continue
            else:
                return '2'  # Return to indicate CSV file selection
        elif choice == '3':
            print("You have selected to exit the tool")
            return '3'  # Return to indicate exit
        else:
            print("Invalid selection. Please try again.")

def format_elapsed(seconds: float) -> str:
    """Format elapsed time as M min S sec."""
    minutes = int(seconds // 60)
    sec = seconds % 60
    if minutes > 0:
        return f"{minutes}m {sec:.2f}s"
    else:
        return f"{sec:.2f}s"

if __name__ == '__main__':
    try:

        start_time = time.perf_counter()  # start timer

        osint_checks = False # Flag to indicate if OSINT checks are performed

        # Load the configuration file to get the queries for incident details
        config = load_config('config.yaml')  # Load the configuration file

        # Allow the user to login to Azure and add the workspaces to a variable for user selection
        print("\nWelcome to the Alert Documentation Tool!")
        print("This tool will help you generate an HTML report based on the detection query results.")
        print("You will be able to select if you want to use the Azure Monitor Logs or a CSV file containing the query results.")

        user_selection = main_menu()

        if user_selection == '1':
            # This selection will run the azure_monitor_logs_query_tool CLI to login to Azure and grab the detection query results

            # ---------------- Azure Monitor Logs Selection ------------ #

                # Close any instances of the query_table.csv file before proceeding
            close_excel_with_file_open("query_table")
                # Start the login process into Azure using the azure_monitor_login CLI
            
            print("\nYou have selected to use Azure Monitor Logs. Please ensure you have the necessary permissions to access the logs (recommended minimum: Log Analytics Reader role on the workspace).")
                # Run the azure_monitor_login CLI to login to Azure to get the workspace ID
            workspace_id = azure_monitor_get_workspace.azure_monitor_login()
                
                # Get the incident details
            incident_no = get_valid_incident_id()
                
                # Get the detection details including start time, end time, and query
            print(f"\nRetrieving detection details for incident ID: {incident_no} in workspace ID: {workspace_id}")

            query = config['incident_details_query'].format(incident_no=incident_no)
            result = azure_monitor_logs_run_query.run_query(workspace_id, query, timespan="P1D")  # Run the query to get the incident details
    
            if not result.get("rows"):
                print("No results returned. Changing the time range from 1 day to 7 days")
                result = azure_monitor_logs_run_query.run_query(workspace_id, query, timespan="P7D")
                if not result.get("rows"):
                    print("No results returned for time range of 7 days... Exiting the tool.")
                    exit(0)

            alerts, alert_id = prepare_results(result)  # Ensure result is in the expected format
            
            query = config['get_alert_link_query'].format(alert_id=alert_id)
            incident_title, query_result, tactics, techniques, product_name, detection_query, query_result_json = run_detection_queries_on_alerts(alerts, workspace_id, query)  # Run detection queries on the alerts

            if product_name.lower().endswith("sentinel"):
                osint_checks = True # Set the flag to indicate OSINT checks will be performed on those alerts where the alert is from Sentinel
            else:
                osint_checks = False  # Set the flag to indicate OSINT checks will not be performed on those alerts where the alert is not from Sentinel

            # ---------------- LLM MITRE ATT&CK Mapping and HTML Output ------------ #

            # Read the events JSON file for the LLM prompt
            with open(query_result_json, "r", encoding="utf-8") as f:
                query_result_json = json.load(f)
            # Get the prompt template and format it with the detection query and incident title
            prompt = config['PROMPT_TEMPLATE_FOR_MITRE_ATTACK_TECHNIQUES'].format(
                events_query=f"KQL:\n{detection_query}\n\nEvents:\n{query_result_json}", alert_title=incident_title
            )

            # ---------------- Investigation Query Pack ------------ #

            print("\nQuerying relevent logs for investigation notes...")
            # Extract entities from the alert
            entities = investigation_query_pack.extract_entities(incident_title, query_result)
            #print(entities)

        elif user_selection == '2':
            beep.beep()     # Play a notification sound for user attention
            csv_data_or_text = input("Do you wish to select a CSV file containing the query results or paste the incident details as text? (Enter 'csv' for file or 'text' for text): ").strip().lower()
            while csv_data_or_text not in ['csv', 'text']:
                beep.beep()     # Play a notification sound for user attention
                csv_data_or_text = input("Invalid selection. Please enter 'csv' for file or 'text' for text: ").strip().lower()
            if csv_data_or_text == 'csv':
                # Close any instances of the query_table.csv file before proceeding
                close_excel_with_file_open("query_table")
                # Get the query results from the CSV file
                query_result, query_result_json = get_query_results_from_file()
            else:
                # If the user chooses to paste the incident details as text, prompt for the text input
                print("Please paste the incident details below (end with an empty line):")
                query_result = ""
                while True:
                    line = input()
                    if line.strip() == "":
                        break
                    query_result += line + "<br />"
                query_result = query_result.strip()
                query_result_json = query_result        # for consistency, set query_result_json to the same value as query_result for mitre_attack_details
            
            # Check if the query result is empty
            if not query_result:
                print("No query results found. Please ensure that the CSV file is in the correct format and contains the necessary data.")
                exit(1)

            beep.beep()     # Play a notification sound for user attention
            print("Please enter the incident number and title for the report.")
            incident_no = input("Incident Number: ").strip()
            beep.beep()     # Play a notification sound for user attention
            incident_title = input("Incident Title: ").strip()
            osint_checks = True  # Set the flag to indicate OSINT checks will be performed

            # Read the events JSON file for the LLM prompt
            with open(query_result_json, "r", encoding="utf-8") as f:
                query_result_json = json.load(f)
            # Get the prompt template and format it with the detection query and incident title
            prompt = config['PROMPT_TEMPLATE_FOR_MITRE_ATTACK_TECHNIQUES'].format(
                events_query=f"Events:\n{query_result_json}", alert_title=incident_title
            )

        elif user_selection == '3':
            print("Exiting the tool. Goodbye!")
            exit(0)

        # ---------------- LLM MITRE ATT&CK Mapping and HTML Output ------------ #
        mitre_attack_map = prompt_for_mitre_attack_techniques(prompt, incident_title=incident_title)

        # ---------------- OSINT Checks ------------ #

        if osint_checks:        # Perform OSINT checks if the flag is set
            # Prompt user for OSINT check confirmation with validation
            while True:
                beep.beep()     # Play a notification sound for user attention
                user_choice = input(
                    "📄 Please review the alert data in the generated Excel/CSV file first.\n"
                    "Would you like to perform OSINT checks on the indicators in this data? (y/n): "
                ).strip().lower()
                if user_choice in ("y", "n"):
                    break
                else:
                    beep.beep()     # Play a notification sound for user attention
                    print("❌ Invalid input. Please enter 'y' for yes or 'n' for no.")
            if user_choice == "y":
                print("[INFO] Starting OSINT checks...")
                # Apply nest_asyncio to allow nested event loops
                nest_asyncio.apply()
                ABIPDB_analysis, skipped_ip_analysis, domain_analysis, hash_analysis = OSINT_check(query_result)  # Perform the OSINT checks
            else:
                print("[INFO] Skipping OSINT checks.")
                # If OSINT checks are not performed, set the analysis variables to empty strings
                ABIPDB_analysis = ""
                skipped_ip_analysis = ""
                domain_analysis = ""
                hash_analysis = ""
        else:       # If OSINT checks are not performed, set the analysis variables to empty strings
            ABIPDB_analysis = ""
            skipped_ip_analysis = ""
            domain_analysis = ""
            hash_analysis = ""

        # ---------------- HTML Build ------------ #

        # Build the HTML content
            # Create an HTML file with the content and save it
        with open("report.html", "w", encoding="utf-8") as file:
            file.write(generate_html_report(incident_no, incident_title, query_result, ABIPDB_analysis, skipped_ip_analysis, domain_analysis, hash_analysis, mitre_attack_map))
        print("\nHTML file 'report.html' created successfully.")

        # ---------------- Show the completed HTML Report ------------ #

        # open the HTML file in browser
        webbrowser.open("report.html")

        # ---------------- End Timer and Complete Execution ------------ #
        end_time = time.perf_counter()  # end timer
        elapsed = end_time - start_time
        beep.beep()     # Play a notification sound for user attention
        print(f"⏱ Execution time: {format_elapsed(elapsed)}\n")

    except Exception as e:
        beep.beep()     # Play a notification sound for user attention
        print(f"Execution error: {e}")