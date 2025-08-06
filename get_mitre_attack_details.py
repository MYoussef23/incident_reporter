import requests
from stix2 import Filter, MemoryStore
import pandas as pd
import fire
from rapidfuzz import fuzz
import re
import ast  # For safe parsing of string-formatted dict/lists from CLI


# Load MITRE ATT&CK Enterprise Matrix (latest version)
def get_attack_store(domain):     # def get_data_from_version(domain, version):
    #"""Get the ATT&CK STIX data for the given version from MITRE/CTI."""
    # Always fetch the latest bundle by omitting the version in the URL
    url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}.json"
    response = requests.get(url)
    # print data to csv
    if response.status_code != 200:
        raise Exception(f"Failed to retrieve STIX bundle: {response.status_code}")
    stix_json = response.json()
    if "objects" not in stix_json:
        print(f"STIX bundle keys: {stix_json.keys()}")
        raise Exception("No 'objects' key in the STIX bundle! Download failed or malformed.")
    return MemoryStore(stix_data=stix_json["objects"])

# Build lookups for techniques and sub-techniques
def build_lookups(attack_store):
    techniques = {}
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
        name = obj.get("name", "")
        # Get the first url in the external references
        # Get the MITRE ATT&CK url in the external references
        url = next(
            (ref.get("url") for ref in obj.get("external_references", [])
            if ref.get("source_name") == "mitre-attack" and "url" in ref),
            None
        )
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase["kill_chain_name"] in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack")
        ]

        techniques[obj["id"]] = {
            "tech_id": ext_id,
            "name": name,
            "url": url,
            "tactics": tactics
        }
    return techniques, tactic_lookup

# Load MITRE ATT&CK Enterprise Matrix (latest version)
def mitre_attack_html_section(techniques):
    """
    Returns an HTML section listing MITRE ATT&CK tactics and techniques, mapped per technique.
    """

    # Define matrices
    matrices = {
        "enterprise-attack": "Enterprise",
        "ics-attack": "ICS",
        "mobile-attack": "Mobile",
    }

    # Build the full table across all domains
    rows = []
    for matrix_key, matrix_name in matrices.items():
        try:
            attack_store = get_attack_store(matrix_key)
        except Exception as e:
            print(f"Error loading {matrix_key}: {e}")
            continue
        techs, tactic_lookup = build_lookups(attack_store)
        for tech in techs.values():
            tech_id = tech['tech_id']
            tech_name = tech['name']
            tech_url = tech.get('url', '')
            tactics = [tactic_lookup.get(t, t) for t in tech['tactics']]
            # Embed the URL as a clickable link in the Technique column
            if tech_url:
                technique_display = f'<a href="{tech_url}" target="_blank">{tech_id}: {tech_name}</a>'
            rows.append({
                "Matrix": matrix_name,
                "Tactic": ", ".join(tactics),
                "Technique": technique_display,
                "TechID": tech_id  # for filtering
            })
    # Create DataFrame
    df = pd.DataFrame(rows, columns=[
        "Matrix", "Tactic", "Technique", "TechID"
    ])

    html_h2 = "<h2>MITRE ATT&CK Mapping</h2>"
    
    # Filter by technique code using the new column
    mask_tech = df["TechID"].isin(techniques)
    filtered_df = df[mask_tech]

    # Drop the TechID column before displaying/saving
    filtered_df = filtered_df.drop(columns=["TechID"])
    filtered_df.to_csv("mitre_techniques_filtered.csv", index=False, encoding="utf-8")

    # Display as HTML table
    html_table = f"{html_h2}\n{filtered_df.to_html(index=False, escape=False)}"
    # print(html_table)     # For debugging, you can uncomment this line to see the HTML output in console
    print("Matrix | Tactic | Technique | URL")
    for _, row in filtered_df.iterrows():
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(row['Technique'], 'html.parser')
        link = soup.a['href'] if soup.a else ''
        text = soup.a.text if soup.a else row['Technique']
        print(f"{row['Matrix']} | {row['Tactic']} | {text} | {link}")

    return html_table

# For debugging, you can uncomment the following lines to export the matrix to a CSV file
# Import json
# def export_matrix_to_csv(domain, csv_filename):
#     """
#     Loads the specified MITRE ATT&CK matrix and exports all techniques to a CSV file.
#     :param domain: The matrix domain, e.g. 'enterprise-attack', 'ics-attack', or 'mobile-attack'
#     :param csv_filename: The output CSV file name
#     """
#     attack_store = get_attack_store(domain)
#     patterns = attack_store.query([Filter("type", "=", "attack-pattern")])
#     rows = []
#     for obj in patterns:
#         # Convert to dict for JSON serialization
#         if hasattr(obj, 'serialize'):
#             raw_dict = obj.serialize()
#             if isinstance(raw_dict, str):
#                 raw_dict = json.loads(raw_dict)
#         elif hasattr(obj, 'to_dict'):
#             raw_dict = obj.to_dict()
#         else:
#             raw_dict = dict(obj)
#         rows.append({
#             "id": raw_dict.get("id", ""),
#             "name": raw_dict.get("name", ""),
#             "raw": json.dumps(raw_dict)
#         })

#     df = pd.DataFrame(rows)
#     df.to_csv(csv_filename, index=False, encoding="utf-8")
#     print(f"Exported {len(df)} techniques to {csv_filename}")

def find_matching_techniques(alert_title, data_block, attack_store, min_score=100):
    """
    Returns a list of MITRE techniques matching keywords in the alert title and data_block.
    """
    # 1. Gather keywords from alert_title and data_block
    keywords = set(re.findall(r'\w+', alert_title))
    # If data_block is a dict (from CLI, parse if string)
    if isinstance(data_block, str):
        try:
            data_block = ast.literal_eval(data_block)
        except Exception:
            data_block = {}

    for val in data_block.values():
        if isinstance(val, list):
            for v in val:
                keywords.update(re.findall(r'\w+', str(v)))
        else:
            keywords.update(re.findall(r'\w+', str(val)))
    keywords = {k.lower() for k in keywords if len(k) > 2}

    # 2. Search techniques
    results = []
    for t in attack_store.query([Filter("type", "=", "attack-pattern")]):
        fields = [
            t.get("name", ""),
            t.get("description", ""),
            " ".join(t.get("x_mitre_detection", [])) if "x_mitre_detection" in t else "",
        ]
        all_text = " ".join(fields).lower()
        matches = []
        for kw in keywords:
            score = fuzz.partial_ratio(kw, all_text)
            if score >= min_score:
                matches.append((kw, score))
        if matches:
            results.append({
                "tech_id": next((r.get("external_id") for r in t.get("external_references", []) if "external_id" in r), None),
                "name": t.get("name"),
                "description": t.get("description", "")[:100] + "...",
                "matched_keywords": matches,
                "url": next((r.get("url") for r in t.get("external_references", []) if r.get("source_name") == "mitre-attack"), ""),
            })
    # Sort by number of matches, then by name
    results = sorted(results, key=lambda x: (-len(x["matched_keywords"]), x["name"]))
    return results

def main(techniques):
    """
    CLI entry point. Pass a comma-separated list of technique IDs, e.g.:
    python get_mitre_attack_details.py main --techniques=T1098,T1203
    """
    
    if isinstance(techniques, str):
        techniques = [t.strip() for t in techniques.split(",")]
    mitre_attack_html_section(techniques)

def main(techniques=None, alert_title=None, data_block=None, min_score=70):
    """
    Usage:
      --techniques=T1021.002,T1210
    OR:
      --alert_title="SMB anomaly traffic" --data_block="{'SourceIP':'10.1.1.1', 'DeviceActions':['drop']}"
    """

    # for testing
    #techniques = "T0853,T1189,T1203"
    #techniques = "T1098"

    # 1. If mapping by alert title/data_block
    if alert_title:
        print("Loading MITRE ATT&CK enterprise-attack matrix...")
        attack_store = get_attack_store("enterprise-attack")
        results = find_matching_techniques(alert_title, data_block or {}, attack_store, min_score=int(min_score))
        if not results:
            print("No MITRE ATT&CK techniques matched this alert.")
            return
        print(f"\nTop {min(10, len(results))} MITRE techniques for alert '{alert_title}':\n")
        for r in results[:10]:
            print(f"{r['tech_id']} | {r['name']} | {r['url']}")
            print(f"  Desc: {r['description']}")
            print(f"  Keywords matched: {r['matched_keywords']}\n")
        # Optional: show as HTML section
        mitre_attack_html_section([r['tech_id'] for r in results[:10] if r['tech_id']])
        return

    # 2. Original behavior: display known techniques
    if techniques:
        if isinstance(techniques, str):
            techniques = [t.strip() for t in techniques.split(",")]
        mitre_attack_html_section(techniques)
    
    #export_matrix_to_csv("ics-attack", "ics_attack_techniques.csv")    # Uncomment to export ICS techniques to CSV

if __name__ == "__main__":
    # Call the function to generate the HTML section
    fire.Fire(main)
