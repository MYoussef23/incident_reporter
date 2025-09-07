# SOC Automation Toolkit

A collection of Python-based automation utilities to support Security Operations Center (SOC) workflows.  
The toolkit focuses on streamlining **incident reporting**, **OSINT enrichment**, and **MITRE ATT&CK mapping**, with integration points for Azure Monitor Logs and local LLMs (Ollama).

---

## 📂 Repository Structure
soc-automation-toolkit/

├── incident_reporter_tool.py # Main tool: generates structured HTML reports for incidents
├── osint_scanner.py # Fire-based CLI for AbuseIPDB & VirusTotal enrichment
├── get_mitre_attack_details.py # Fetches MITRE ATT&CK STIX data & builds mappings
├── ollama_prompt.py # Safe wrapper for local Ollama LLM (JSON output, retries)
├── beep.py # Simple cross-platform terminal beep utility
├── config.yaml # Configuration file for queries & API keys

---

## 🚀 Tools Overview

### 1. Incident Reporter Tool (`incident_reporter_tool.py`)
- Generates analyst-ready **HTML reports** from:
  - Azure Monitor Log queries
  - CSV uploads
  - Manual event data
- Runs **OSINT enrichment** (AbuseIPDB + VirusTotal).
- Performs **MITRE ATT&CK mapping** using:
  - `get_mitre_attack_details.py` (STIX lookup)
  - `ollama_prompt.py` (local Ollama LLM)
- Produces structured output with:
  - Events
  - OSINT checks
  - ATT&CK mapping
  - Investigation notes
  - Conclusion & next actions

### 2. OSINT Scanner (`osint_scanner.py`)
- Fire-based CLI for **enriching IOCs**:
  - IP addresses → AbuseIPDB
  - Domains → VirusTotal
  - File hashes → VirusTotal (with sandbox verdicts)
- Supports:
  - CIDR/org domain allowlists to avoid self-traffic
  - CSV export of results
  - Reading targets from text files
- Includes **backward compatibility wrappers** so it can be called directly from `incident_reporter_tool.py`.

Example:
```bash
python osint_scanner.py ip --targets_file ips.txt --output_csv results/abuseipdb.csv
### 3. MITRE ATT&CK Mapping Utility (get_mitre_attack_details.py)
- Downloads MITRE ATT&CK STIX data (v17.1).
- Maps alerts or extracted techniques to relevant ATT&CK tactics/techniques.
- Outputs:
  - CSV tables
  - HTML sections for embedding in reports
  - Supports fuzzy keyword matching against alert titles and data.

### 4. Ollama Prompt Wrapper (ollama_prompt.py)
- Lightweight wrapper for local Ollama LLM (default: llama3.1).
- Ensures safe retries with memory error handling.
- Returns JSON-formatted content for downstream parsing.
- Designed for SOC automation pipelines where structured output is needed.
Example:
```bash
python ollama_prompt.py run_ollama --prompt "Map this alert to MITRE ATT&CK" --ollama_model llama3.1
```
### 5. Beep Utility (beep.py)
- Minimal helper to play a terminal beep (\a).
- Used across scripts to notify the analyst during interactive prompts.
## ⚙️ Setup & Requirements
### Install dependencies
```bash
pip install -r requirements.txt
```
Typical requirements include:
- `requests`
- `pandas`
- `fire`
- `vt-py`
- `stix2`
- `rapidfuzz`
- `pyyaml`
- `beautifulsoup4`
- `nest_asyncio`
- (Windows only) `pywin32`
### Config (config.json and config.yaml)
Define API keys in a config.json file:
```json
{
  "VT_api_key": "your-virustotal-api-key"
  "ABDB_api_key": "your-abuseipdb-api-key"
```
Prompt template for MITRE ATT&CK Mapping
```yaml
PROMPT_TEMPLATE_FOR_MITRE_ATTACK_TECHNIQUES: |
  You are a SOC analyst. Map the following alert to MITRE ATT&CK:
  Version: ${MITRE_VERSION}
  Title: ${ALERT_TITLE}
  Details: ${ALERT_DETAILS}
```
## 📝 Usage Examples
### Generate an Incident Report
```bash
python incident_reporter_tool.py
```
- Choose Azure Monitor Logs or CSV/manual input.
- Optionally run OSINT checks and MITRE mapping.
- Outputs report.html.
### Run OSINT Scanner
```bash
# IP mode
python osint_scanner.py ip --targets 8.8.8.8 1.1.1.1 --output_csv results/abuseipdb.csv --abuseipdb_api_key YOUR_KEY

# Domain mode
python osint_scanner.py domain --targets malicious.com --vt_api_key YOUR_KEY

# Hash mode
python osint_scanner.py hash --targets d41d8cd98f00b204e9800998ecf8427e --vt_api_key YOUR_KEY
```
### MITRE ATT&CK Mapping
```bash
python get_mitre_attack_details.py --techniques T1021.002,T1210
```
##🔔 Attribution
- The OSINT Scanner was inspired by [https://github.com/jade-hill-sage/OSINT-Scanner](OSINT_Scanner) by Jade Hill.
- MITRE ATT&CK data is sourced from mitre-attack/attack-stix-data.
- Ollama integration requires a local Ollama installation.
## 📜 License
MIT License - see LICENSE for details.
## 🙌 Contributing
Pull requests and issues are welcome!
Ideas for expansion:
  - Additional OSINT integrations (Shodan, GreyNoise, etc.)
  - More ATT&CK mapping logic
  - GUI dashboard for incident report output
