#!/usr/bin/env python3
import json
import os
import ollama
from openai import OpenAI
import fire  # pip install fire
import yaml

# ollama run llama3

# Function to load the configuration from a JSON file
def load_config(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Configuration file not found: {file_path}")

    with open(file_path, "r") as f:
        data = f.read()
        try:
            config = yaml.safe_load(data)
            return config
        except yaml.YAMLError as e:
            raise ValueError(f"Error parsing the YAML configuration file: {e}")

def run_ollama(prompt: str, model: str):
    print(f"\n[Prompting Ollama local LLM: {model}]\n")
    response = ollama.chat(model=model, messages=[{"role": "user", "content": prompt}])
    return response["message"]["content"]

def _extract_text_from_responses(resp):
    # Prefer the canned field if present
    if hasattr(resp, "output_text") and resp.output_text:
        return resp.output_text

    # Otherwise concatenate any text parts we find
    parts = []
    try:
        for item in getattr(resp, "output", []) or []:
            for c in getattr(item, "content", []) or []:
                t = getattr(c, "text", None)
                if t:
                    parts.append(t)
    except Exception:
        pass

    return "\n".join(parts).strip() or str(resp)

def run_openai(prompt: str, model: str, api_key: str, fallback_ollama_model: str = "llama3"):
    print(f"\n[Prompting OpenAI model: {model}]\n")
    client = OpenAI(api_key=api_key)
    try:
        # Use OpenAI's chat completion API
        resp = client.responses.create(
            model=model,
            input=prompt,
            temperature=0,
            max_output_tokens=200
        )
        text = _extract_text_from_responses(resp).strip()
        if not text:
            raise RuntimeError("Empty OpenAI response text")
        return text
    except Exception as e:
        # Prefer specific fallback logic on quota/rate issues
        err_str = str(e).lower()
        if ("insufficient_quota" in err_str or "status code: 429" in err_str or "rate limit" in err_str):
            print("OpenAI quota/rate issue detected. Falling back to Ollama...")
        else:
            print(f"OpenAI call failed ({e}). Falling back to Ollama...")

        # Fall back to local model
        return run_ollama(prompt, model=fallback_ollama_model)

def extract_techniques(text: str):
    lines = [ln.strip() for ln in text.splitlines()]
    return [ln for ln in lines if ln and ln[0].upper() == "T"]

def mitre_mapper(alert_title, detection_json_path, provider="ollama",
                 ollama_model="llama3", openai_model="gpt-4.1", openai_api_key=None):
    """Map alerts to MITRE ATT&CK techniques via Ollama or OpenAI."""
    
    if not openai_api_key:
        openai_api_key = os.getenv("OPENAI_API_KEY")

    # Load the configuration file
    config = load_config('config.yaml')

    if provider == "ollama":
        # get the prompt template from the config file
        prompt_template = config['PROMPT_TEMPLATE_WITH_DETECTION_DATA']
        # Check if detection_json_path has the extension .json
        if not detection_json_path.endswith('.json'):
            # Treat as a block of text
            prompt = prompt_template.format(
                alert_title=alert_title,
                detection_data=detection_json_path
            )
        else:
            # Load the JSON data from the file
            if not os.path.exists(detection_json_path):
                raise FileNotFoundError(f"Detection JSON file not found: {detection_json_path}")
            # Load the JSON data
            with open(detection_json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            detection_data = data[0] if isinstance(data, list) else data
            prompt = prompt_template.format(
                alert_title=alert_title,
                detection_data=json.dumps(detection_data, indent=2)
            )
        output = run_ollama(prompt, ollama_model)
    elif provider == "openai":
        if not openai_api_key:
            raise SystemExit("ERROR: Provide OpenAI API key via argument or OPENAI_API_KEY env var")
        # get the prompt template from the config file
        prompt_template = config['PROMPT_TEMPLATE_WITH_ALERT_DETAILS']
        prompt = prompt_template.format(
            alert_title=alert_title,
            detection_data=detection_json_path
        )
        output = run_openai(prompt, openai_model, openai_api_key)
    else:
        raise SystemExit("Invalid provider: choose 'ollama' or 'openai'")

    techniques = extract_techniques(output)
    print("\n--- MITRE ATT&CK Techniques ---\n")
    for t in techniques:
        print(t)
    return techniques

if __name__ == "__main__":
    fire.Fire(mitre_mapper)
