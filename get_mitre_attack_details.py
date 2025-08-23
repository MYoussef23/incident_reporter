import requests
from stix2 import Filter, MemoryStore
import pandas as pd
import fire
from rapidfuzz import fuzz
import re
import ast  # For safe parsing of string-formatted dict/lists from CLI


# Load MITRE ATT&CK Enterprise Matrix (latest version)
def get_attack_store(domain, version="17.1"):     # Get the latest version, which is 17.1 as per https://github.com/mitre-attack/attack-stix-data/tree/master
    #"""Get the ATT&CK STIX data for the given version from MITRE/CTI."""
    # Always fetch the latest bundle by omitting the version in the URL
    url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}/{domain}-{version}.json"
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

def mitre_attack_html_section(techniques):
    """
    Returns an HTML section listing MITRE ATT&CK tactics and techniques, 
    mapped per technique ID and description.

    Parameters:
        techniques (list of tuple): List of (technique_id, description).
    """

    # Define matrices
    matrices = {
        "enterprise-attack": "Enterprise",
        "ics-attack": "ICS",
        "mobile-attack": "Mobile",
    }

    # Extract technique IDs and description mapping
    tech_ids = [tech_id.strip() for tech_id, _ in techniques]
    descriptions_map = {tech_id.strip(): desc.strip() for tech_id, desc in techniques}

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

            # Embed the URL as a clickable link
            if tech_url:
                technique_display = f'<a href="{tech_url}" target="_blank">{tech_id}: {tech_name}</a>'
            else:
                technique_display = f"{tech_id}: {tech_name}"

            rows.append({
                "Matrix": matrix_name,
                "Tactic": ", ".join(tactics),
                "Technique": technique_display,
                "TechID": tech_id,
                "Relevance to the Alert": descriptions_map.get(tech_id, "")
            })

    # Create DataFrame
    df = pd.DataFrame(rows, columns=["Matrix", "Tactic", "Technique", "TechID", "Relevance to the Alert"])

    # Filter by technique ID
    mask_tech = df["TechID"].isin(tech_ids)
    filtered_df = df[mask_tech]

    # Save CSV without TechID column
    filtered_df.drop(columns=["TechID"], inplace=True)
    filtered_df.to_csv("mitre_techniques_filtered.csv", index=False, encoding="utf-8")

    # Build HTML table
    html_h2 = "<h2>MITRE ATT&CK Mapping</h2>"
    html_table = f"{html_h2}\n{filtered_df.to_html(index=False, escape=False)}"

    # Console print
    print("Matrix | Tactic | Technique | Relevance to the Alert | URL")
    for _, row in filtered_df.iterrows():
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(row['Technique'], 'html.parser')
        link = soup.a['href'] if soup.a else ''
        text = soup.a.text if soup.a else row['Technique']
        print(f"{row['Matrix']} | {row['Tactic']} | {text} | {row['Relevance to the Alert']} | {link}")

    return html_table

def find_matching_techniques(alert_title, data_block, min_score=100):
    """
    Returns a list of MITRE techniques matching keywords in the alert title and data_block
    across all ATT&CK matrices.
    """
    matrices = {
        "enterprise-attack": "Enterprise",
        "ics-attack": "ICS",
        "mobile-attack": "Mobile",
    }

    # 1. Gather keywords from alert_title and data_block
    keywords = set(re.findall(r'\w+', alert_title))
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

    # 2. Search techniques in all matrices
    all_results = []
    for matrix_key, matrix_name in matrices.items():
        attack_store = get_attack_store(matrix_key)
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
                all_results.append({
                    "matrix": matrix_name,
                    "tech_id": next((r.get("external_id") for r in t.get("external_references", []) if "external_id" in r), None),
                    "name": t.get("name"),
                    "description": t.get("description", "")[:100] + "...",
                    "matched_keywords": matches,
                    "url": next((r.get("url") for r in t.get("external_references", []) if r.get("source_name") == "mitre-attack"), ""),
                })
    # Sort by number of matches, then by name
    all_results = sorted(all_results, key=lambda x: (-len(x["matched_keywords"]), x["name"]))

    if not all_results:
        print("No MITRE ATT&CK techniques matched this alert.")
        html_table = "<h2>No matching MITRE ATT&CK techniques found</h2>"
        return html_table

    print(f"\nTop {min(10, len(all_results))} MITRE techniques for alert '{alert_title}':\n")
    for r in all_results[:10]:
        print(f"{r['tech_id']} | {r['name']} | {r['url']}")
        print(f"  Desc: {r['description']}")
        print(f"  Keywords matched: {r['matched_keywords']}\n")
    
    # show as HTML section
    html_table = mitre_attack_html_section([r['tech_id'] for r in all_results[:10] if r['tech_id']])
    
    return html_table

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
        print("Finding matching MITRE ATT&CK techniques for the alert...")
        #attack_store = get_attack_store("enterprise-attack")
        find_matching_techniques(alert_title, data_block or {}, min_score=int(min_score))
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
