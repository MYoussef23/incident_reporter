import json
import ollama  # pip install ollama
import re

PROMPT_TEMPLATE = """
Given the following security alert and context, determine the most relevant MITRE ATT&CK technique(s):

Alert Title: {alert_title}
Detection Data: {detection_data}

Respond as a list of technique ID's. Only show relevant technique(s) and only output the technique number(s) (no extra text or explanations).
"""

def extract_mitre_table(llm_response):
    # Simple regex to extract <table>...</table> from LLM output
    match = re.search(r"<table[\s\S]*?</table>", llm_response, re.IGNORECASE)
    if match:
        return match.group(0)
    # fallback: return raw
    return llm_response

def main(alert_title, detection_json_path, ollama_model="llama3"):
    # Load detection data (first object if list)
    with open(detection_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    detection_data = data[0] if isinstance(data, list) else data

    prompt = PROMPT_TEMPLATE.format(
        alert_title=alert_title,
        detection_data=json.dumps(detection_data, indent=2)
    )

    print("\n[Prompting Ollama local LLM...]\n")
    response = ollama.chat(model=ollama_model, messages=[{"role": "user", "content": prompt}])
    output = response["message"]["content"]

    #html_table = extract_mitre_table(output)
    # Get output as list of techniques
    techniques = output.strip().splitlines()
    techniques = [t.strip() for t in techniques if t.strip()]
    print("\n--- MITRE ATT&CK Mapping (HTML) ---\n")
    print(techniques)
    return techniques

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python mitre_ollama_html.py '<ALERT_TITLE>' <DETECTION_JSON_PATH> [ollama_model]")
        print("Example: python mitre_ollama_html.py 'DXC - Front Door Premium WAF - XSS Detection' output.json llama3")
        sys.exit(1)
    alert_title = sys.argv[1]
    detection_json_path = sys.argv[2]
    ollama_model = sys.argv[3] if len(sys.argv) > 3 else "llama3"
    main(alert_title, detection_json_path, ollama_model)
