# Prerequisites:
# 1. Python 3.x installed on your system.
# 2. Required libraries installed (see requirements.txt).
# 3. A configuration file named config.json with the necessary API keys and script paths.

# Imports for the Azure/OSINT check functions
import os
import sys
from html import escape
from collections import defaultdict
import json
import yaml
import requests
import re
import azure_monitor_get_workspace
import azure_monitor_logs_run_query
import iocextract
import osint_scanner
import vt
import asyncio
import nest_asyncio
import subprocess
import ipaddress
from ipwhois import IPWhois
import socket
from urllib.parse import urlparse
import warnings
from urllib3.exceptions import InsecureRequestWarning
# Import for the CSV file handling
import csv
from tkinter import Tk, filedialog
import pandas as pd
import win32com.client
import ast
from stix2 import Filter, MemoryStore
from thefuzz import fuzz
from collections import defaultdict

warnings.simplefilter('ignore', InsecureRequestWarning)

# Function to install requirements from a requirements.txt file
def install_requirements():
    req_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    if os.path.exists(req_file):
        try:
            import pkg_resources
            with open(req_file) as f:
                packages = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            installed = {pkg.key for pkg in pkg_resources.working_set}
            missing = [pkg for pkg in packages if pkg.split("==")[0].lower() not in installed]
            if missing:
                print(f"Installing missing packages: {missing}")
                subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
        except Exception as e:
            print(f"Could not check/install requirements: {e}")

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
        user_continue = input(f"\nYou have selected Incident ID: {incident_id}. Do you want to continue? (Y/N): ").strip().lower()
        if user_continue in ['y', 'yes']:
            return incident_id  # Proceed with this incident ID
        elif user_continue in ['n', 'no']:
            print("Let's enter a different Incident ID.")
            continue
        else:
            print("Invalid input. Please enter 'Y' to continue or 'N' to re-enter the Incident ID.")

def get_incident_number():      # This will loop till the user enters a valid entry which is a positive integer (Sentinel works off positive integer incident number types)
    while True:
            incident_id = input("Enter the Incident ID: ").strip()
            try:
                incident_id = int(incident_id)
                if incident_id > 0:
                    return incident_id
                else:
                    print("Incident ID must be a positive integer.")
            except ValueError:
                print("Please enter a valid numeric Incident ID.")

def save_to_csv(table, filename):
    # put table data in dataframe
    df = pd.DataFrame(table["rows"], columns=[col["name"] for col in table["columns"]])
    # Save dataframe as CSV
    df.to_csv(filename, index=False)

# Load MITRE ATT&CK Enterprise Matrix (latest version)
def get_attack_store(domain):
    # Always fetch the latest bundle by omitting the version in the URL
    url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json"
    response = requests.get(url)

    if response.status_code != 200:     # Check if the request was successful
        raise Exception(f"Failed to retrieve STIX bundle: {response.status_code}")
    stix_json = response.json()

    if "objects" not in stix_json:      # Check if the 'objects' key does not exist in the JSON response
        print(f"STIX bundle keys: {stix_json.keys()}")
        raise Exception("No 'objects' key in the STIX bundle! Download failed or malformed.")
    
    # ---- Print domain if available ----
    domain = stix_json.get("domain", "Unknown")
    if domain:
        print(f"Domain: {domain}")
    
    # ---- Print version if available ----
    version = None
    for obj in stix_json["objects"]:
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version")
            if version:
                print(f"{domain} dataset version loaded: {version}")
            break
    if not version:
        print(f"{domain} dataset version: Unknown")
    # ------------------------------------

    # Return a MemoryStore with the STIX data
    return MemoryStore(stix_data=stix_json["objects"])

# Build lookups for techniques and sub-techniques
def build_lookups(attack_store):
    techniques = {}
    subtechniques = defaultdict(list)
    tactic_lookup = {}
    patterns = attack_store.query([Filter("type", "=", "attack-pattern")])
    # Get tactics (to display nice names)
    for tactic in attack_store.query([Filter("type", "=", "x-mitre-tactic")]):
        shortname = tactic.get("x_mitre_shortname", tactic["id"])
        tactic_lookup[shortname] = tactic["name"]
    for obj in patterns:
        ext_id = next((ref.get("external_id") for ref in obj.get("external_references", []) if "external_id" in ref), None)
        if not ext_id:
            continue
        is_sub = obj.get("x_mitre_is_subtechnique", False)
        name = obj.get("name", "")
        desc = obj.get("description", "")
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase["kill_chain_name"] == "mitre-attack"
        ]
        if is_sub:
            parent = obj.get("x_mitre_parent_technique_ref")
            if parent:
                subtechniques[parent].append((ext_id, name, desc))
        else:
            techniques[obj["id"]] = {
                "tech_id": ext_id,
                "name": name,
                "desc": desc,
                "tactics": tactics
            }
    return techniques, subtechniques, tactic_lookup

# Load MITRE ATT&CK Enterprise Matrix (latest version)
def mitre_attack_html_section(tactics, techniques, lookup_names=True):
    """
    Returns an HTML section listing MITRE ATT&CK tactics and techniques, mapped per technique.
    """
    mitre_attack_h2 = "<h2>MITRE ATT&CK Mapping</h2>"

    # Define matrices
    matrices = {
        "enterprise-attack": "Enterprise",
        "ics-attack": "ICS",
        "mobile-attack": "Mobile",
        "pre-attack": "PRE-ATT&CK"
    }

    # Build the full table across all domains
    rows = []
    for matrix_key, matrix_name in matrices.items():
        try:
            attack_store = get_attack_store(matrix_key)
        except Exception as e:
            print(f"Error loading {matrix_key}: {e}")
            continue
        techs, subtechniques, tactic_lookup = build_lookups(attack_store)
        for tech in techs.values():
            tech_id = tech['tech_id']
            tech_name = tech['name']
            # If technique description output is desired, uncomment the next lines
            """
            tech_desc = tech['desc']
            # Replace Markdown-style links with HTML links
            tech_desc = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', tech_desc)
            # Replace newline characters with <br />
            tech_desc = tech_desc.replace('\n\n', '<br /><br />').replace('\n', '<br />')
            """
            tactics = [tactic_lookup.get(t, t) for t in tech['tactics']]
            # Find the parent_id in this domain for sub-techniques
            parent_id = next((k for k, v in techniques.items() if v['tech_id'] == tech_id), None)
            subtechs = subtechniques.get(parent_id, [])
            if not subtechs:
                rows.append({
                    "Matrix": matrix_name,
                    "Tactic": ", ".join(tactics),
                    "Technique": f"{tech_id}: {tech_name}",
                    # "Technique Description": tech_desc,       # Uncomment if description is needed
                    "Sub-Techniques": "",
                    # "Sub-Technique Description": ""   # Uncomment if description is needed
                })
            else:
                for sub_id,sub_name in subtechs:        # Add sub_desc if a description column is needed
                    rows.append({
                        "Matrix": matrix_name,
                        "Tactic": ", ".join(tactics),
                        "Technique": f"{tech_id}: {tech_name}",
                        #"Technique Description": tech_desc,        # Uncomment if description is needed
                        "Sub-Techniques": f"{sub_id}: {sub_name}"#, # Add comma if a description column is needed
                        # "Sub-Technique Description": sub_desc     # Uncomment if description is needed
                    })

    # Create DataFrame
    df = pd.DataFrame(rows, columns=[
        "Matrix", 
        "Tactic", 
        "Technique", 
        # "Technique Description",      # Uncomment if description is needed 
        "Sub-Techniques"#,            # Add comma if a description column is needed       
        # "Sub-Technique Description"   # Uncomment if description is needed
    ])

    # Filter techniques if provided
    if techniques:
        if isinstance(techniques, str):
            # If a single technique code is provided as a string, convert to list
            try:
                techniques = ast.literal_eval(techniques)
            except Exception:
                techniques = [techniques]
    
    # Filter by technique code
    filtered_df = df[df["Technique"].str.split(":").str[0].isin(techniques)]

    # Display as HTML table
    html_table = f"{mitre_attack_h2}\n{filtered_df.to_html(index=False, escape=False)}"
    print(html_table)

    return html_table

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
        return query_result

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
            save_to_csv(query_table, csv_filename)
            print(f"\nQuery result saved to {csv_filename}")

            # Open the file in default CSV viewer
            print(f"Opening query result file: {csv_filename}...")
            os.startfile(csv_filename)

            # Normalise query_result into HTML format
            columns = [col["name"] for col in query_table["columns"]]
            rows = query_table["rows"]
            query_result = "<br />".join(
                [",".join(columns)] +
                [",".join(str(cell) for cell in row) for row in rows]
            )
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
    
    return alerts[0]["IncidentTitle"], all_query_results, tactics, techniques, product_name

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
        print("\nMain Menu:")
        print("1. Use Azure Monitor Logs to obtain the detection query results")
        print("2. Use a CSV file containing the query results")
        print("3. Exit the tool")
        choice = input("Enter your choice (1/2/3): ").strip()
        
        if choice == '1':
            # Handle Azure Monitor Logs
            user_selection = input("You have selected to use Azure Monitor Logs. Do you wish to continue? (Y/N)\n " \
                                    "Enter 'Y' to continue or 'N' to return to the main menu: ").strip().lower()
            while user_selection not in ['yes', 'y', 'no', 'n']:
                user_selection = input("Invalid selection. Please enter 'yes' or 'no': ").strip().lower()
            if user_selection in ['no', 'n']:
                print("Returning to the main menu...")
                continue
            else:
                return '1'  # Return to indicate Azure Monitor Logs selection
        elif choice == '2':
            # Handle CSV file input
            user_selection = input("You have selected to use a CSV file containing the query results. Do you wish to continue? (Y/N)\n " \
                                    "Enter 'Y' to continue or 'N' to return to the main menu: ").strip().lower()
            while user_selection not in ['yes', 'y', 'no', 'n']:
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

if __name__ == '__main__':
    try:
        # Install the required libraries from requirements.txt if not already installed
        install_requirements()
        osint_checks = False # Flag to indicate if OSINT checks are performed

        # Allow the user to login to Azure and add the workspaces to a variable for user selection
        print("\nWelcome to the Alert Documentation Tool!")
        print("This tool will help you generate an HTML report based on the detection query results.")
        print("You will be able to select if you want to use the Azure Monitor Logs or a CSV file containing the query results.")

        user_selection = main_menu()

        if user_selection == '1':
            # This selection will run the azure_monitor_logs_query_tool CLI to login to Azure and grab the detection query results
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
                # Load the configuration file to get the queries for incident details
            config = load_config('config.yaml')  # Load the configuration file

            query = config['incident_details_query'].format(incident_no=incident_no)
            result = azure_monitor_logs_run_query.run_query(workspace_id, query, timespan="P30D")  # Run the query to get the incident details
    
            if not result.get("rows"):
                print("No results returned. Changing the time range from 1 day to 7 days")
                result = azure_monitor_logs_run_query.run_query(workspace_id, query, timespan="P7D")
                if not result.get("rows"):
                    print("No results returned for time range of 7 days... Exiting the tool.")
                    exit(0)

            alerts, alert_id = prepare_results(result)  # Ensure result is in the expected format
            
            query = config['get_alert_link_query'].format(alert_id=alert_id)
            incident_title, query_result, tactics, techniques, product_name = run_detection_queries_on_alerts(alerts, workspace_id, query)  # Run detection queries on the alerts
            if product_name.lower().endswith("sentinel"):
                osint_checks = True # Set the flag to indicate OSINT checks will be performed on those alerts where the alert is from Sentinel
            else:
                osint_checks = False  # Set the flag to indicate OSINT checks will not be performed on those alerts where the alert is not from Sentinel
            
            #mitre_attack_map = mitre_attack_html_section(tactics, techniques)
            mitre_attack_map = ""
        elif user_selection == '2':
            print("Please ensure that the CSV file is in the correct format and contains the necessary data.")
            query_result = get_query_results_from_file()  # Get the query results from the CSV file
            print("Please enter the incident number and title for the report.")
            incident_no = input("Incident Number: ").strip()
            incident_title = input("Incident Title: ").strip()
            osint_checks = True  # Set the flag to indicate OSINT checks will be performed
            mitre_attack_map = ""
        elif user_selection == '3':
            print("Exiting the tool. Goodbye!")
            exit(0)
        
        if osint_checks:        # Perform OSINT checks if the flag is set
            # Apply nest_asyncio to allow nested event loops
            nest_asyncio.apply()
            #ABIPDB_analysis, skipped_ip_analysis, domain_analysis, hash_analysis = asyncio.run(OSINT_check(query_result))  # Perform the OSINT checks
            ABIPDB_analysis, skipped_ip_analysis, domain_analysis, hash_analysis = OSINT_check(query_result)  # Perform the OSINT checks
        else:       # If OSINT checks are not performed, set the analysis variables to empty strings
            ABIPDB_analysis = ""
            skipped_ip_analysis = ""
            domain_analysis = ""
            hash_analysis = ""

        # Build the HTML content
            # Create an HTML file with the content and save it
        with open("sample.html", "w", encoding="utf-8") as file:
            file.write(generate_html_report(incident_no, incident_title, query_result, ABIPDB_analysis, skipped_ip_analysis, domain_analysis, hash_analysis, mitre_attack_map))
        print("\nHTML file 'sample.html' created successfully. \n" \
                "Ensure you close any open instances of the file before running the script again.")

        # open the HTML file in notepad
        os.system("notepad sample.html")

    except Exception as e:
        print(f"Execution error: {e}")