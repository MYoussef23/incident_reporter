#!/usr/bin/env python3
import os
import sys
import csv
import json
import shutil
import subprocess
from typing import Optional
from beep import beep

import requests

try:
    from beep import beep  # optional convenience
    _HAS_BEEP = True
except Exception:
    _HAS_BEEP = False

# ---------- Helper: resolve Azure CLI executable ----------
def _az_exe() -> str:
    """
    Returns a usable Azure CLI executable path.
    Prefers the Windows az.cmd if present; falls back to 'az' on PATH.
    """
    windows_az = r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
    if os.name == "nt" and os.path.exists(windows_az):
        return windows_az
    found = shutil.which("az")
    if found:
        return found
    raise RuntimeError("Azure CLI not found. Please install Azure CLI and ensure it is on PATH.")

# ---------- Core auth/token helpers ----------
def get_access_token(resource: str) -> Optional[str]:
    """
    Acquire an access token for the given Azure resource using Azure CLI.
    """
    try:
        access_token = subprocess.check_output(
            [_az_exe(), "account", "get-access-token", "--resource", resource, "--query", "accessToken", "-o", "tsv"],
            text=True
        ).strip()
        return access_token
    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve access token for {resource}. Details:\n{e.output}", file=sys.stderr)
        return None

def is_token_valid(resource: str) -> bool:
    """
    Performs a quick check that the token is accepted by Azure ARM (expects 400 for incomplete request).
    """
    try:
        token = get_access_token(resource)
        if token is None:
            return False
        headers = {"Authorization": f"Bearer {token}"}
        # Harmless probe; ARM returns 400 for missing parameters when token is valid
        resp = requests.get("https://management.azure.com/", headers=headers, timeout=5)
        if resp.status_code != 400:
            print(f"Token for {resource} is invalid (status {resp.status_code})")
            return False
        return True
    except (subprocess.CalledProcessError, requests.RequestException):
        return False

def get_azure_account_name() -> Optional[str]:
    """
    Returns the current Azure CLI account user name (UPN/email).
    """
    try:
        account_name = subprocess.check_output(
            [_az_exe(), "account", "show", "--query", "user.name", "-o", "tsv"],
            text=True
        ).strip()
        return account_name
    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve account name: {e.output}", file=sys.stderr)
        return None

def _maybe_beep():
    if _HAS_BEEP:
        try:
            beep()
        except Exception:
            pass

def prompt_change_account(account: str) -> bool:
    """
    Interactive prompt to continue with current account.
    Returns True if user wants to continue with the current account.
    """
    print(f"Current Azure account: {account}")
    while True:
        _maybe_beep()
        answer = input("Do you want to continue using this account? (Y/N): ").strip().lower()
        if answer in ("y", "yes", "n", "no"):
            return answer in ("y", "yes")
        _maybe_beep()
        print("Please enter 'y' for yes or 'n' for no.")

def Azure_scope_login(scope: str):
    """
    Launch Azure CLI login with provided scope (usually '<resource>/.default').
    """
    subprocess.run([_az_exe(), "login", "--scope", scope], check=True)

def check_for_valid_session_tokens(resource: str):
    """
    Validate current token; prompt to continue or login as needed.
    """
    if is_token_valid(resource):
        print(f"Session token for {resource} is still valid.")
        account = get_azure_account_name()
        if account:
            continue_with_account = prompt_change_account(account)
            if not continue_with_account:
                print("Please login with a different account.")
                Azure_scope_login(resource + "/.default")
            else:
                print("Continuing with current account.")
        else:
            print("Could not determine current account; continuing.")
    else:
        print(f"Session token for {resource} is invalid or expired. Please login again.")
        Azure_scope_login(resource + "/.default")

# ---------- Log Analytics query ----------
def _query_log_analytics(workspace_id: str, query: str, timespan: str, verify_tls: bool) -> dict:
    """
    Calls the Log Analytics Query REST API and returns the JSON payload (dict).
    """
    resource = "https://api.loganalytics.io"
    # Ensure valid session/token
    if is_token_valid(resource):
        token = get_access_token(resource)
    else:
        check_for_valid_session_tokens(resource)
        token = get_access_token(resource)

    if token is None:
        raise RuntimeError("Unable to acquire access token after login attempt.")

    url = f"{resource}/v1/workspaces/{workspace_id}/query"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = {"query": query, "timespan": timespan}

    # NOTE: original script used verify=False; keep it configurable (default True)
    resp = requests.post(url, headers=headers, json=body, verify=verify_tls)
    if resp.status_code != 200:
        raise RuntimeError(f"Error querying Log Analytics: {resp.status_code} {resp.text}")
    return resp.json()

def _extract_first_table(result_json: dict) -> Optional[dict]:
    tables = result_json.get("tables", [])
    if not tables:
        return None
    return tables[0]

def _print_table(table: dict, sep: str = " | "):
    cols = [c["name"] for c in table.get("columns", [])]
    rows = table.get("rows", [])
    print(sep.join(cols))
    print("-" * min(120, len(sep.join(cols)) + 4))
    for r in rows:
        print(sep.join(str(cell) for cell in r))

def _table_to_csv(table: dict, path: str):
    cols = [c["name"] for c in table.get("columns", [])]
    rows = table.get("rows", [])
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        for r in rows:
            writer.writerow(r)

# ---------- Python Fire CLI ----------
class AzureMonitorCLI:
    """
    Azure Log Analytics (Sentinel) helper CLI.

    Commands:
      run_query           Run a KQL query against a Log Analytics workspace.
      token               Print whether the token for a resource is valid; optionally return token.
      account             Show current Azure CLI account name.
      login               Trigger interactive az login for a given scope.
      check_session       Validate/refresh session for a resource.
    """

    def run_query(
        self,
        workspace_id: str,
        query: str,
        timespan: str,
        output: str = "table",
        csv_path: Optional[str] = None,
        sep: str = " | ",
        verify_tls: bool = True,
    ):
        """
        Run a KQL query.

        Args:
          workspace_id: Log Analytics Workspace ID (GUID).
          query:        KQL query string.
          timespan:     ISO8601 timespan (e.g., 'P1D') or 'YYYY-MM-DDTHH:MM:SSZ/YYYY-MM-DDTHH:MM:SSZ'.
          output:       'table' (default), 'json', or 'csv'.
          csv_path:     If provided (or output='csv'), write CSV to this path.
          sep:          Column separator for 'table' rendering.
          verify_tls:   Verify TLS certs for HTTPS requests (default True; set False to mimic original script).
        """
        result = _query_log_analytics(workspace_id, query, timespan, verify_tls=verify_tls)
        table = _extract_first_table(result)
        if not table:
            print("No data returned from the query.")
            return

        out = output.lower()
        if out == "table":
            _print_table(table, sep=sep)
        elif out == "json":
            print(json.dumps(table, indent=2, ensure_ascii=False))
        elif out == "csv":
            path = csv_path or "log_analytics_query.csv"
            _table_to_csv(table, path)
            print(f"Wrote CSV: {path}")
        else:
            print(f"Unknown output format '{output}'. Use 'table', 'json', or 'csv'.")

    def token(self, resource: str = "https://api.loganalytics.io", show: bool = False):
        """
        Check token validity for a resource; optionally print the token.

        Args:
          resource: Azure resource audience (default: Log Analytics API).
          show:     If True, prints the raw access token (handle with care).
        """
        valid = is_token_valid(resource)
        print(f"Token valid for {resource}: {valid}")
        if show and valid:
            tok = get_access_token(resource)
            print(tok or "")

    def account(self):
        """
        Print current Azure CLI account user.name.
        """
        acct = get_azure_account_name()
        print(acct or "Unknown")

    def login(self, scope: str = "https://api.loganalytics.io/.default"):
        """
        Run 'az login' with the provided scope.
        """
        Azure_scope_login(scope)
        print("Login completed.")

    def check_session(self, resource: str = "https://api.loganalytics.io"):
        """
        Validate current session/token and prompt for login/account change as needed.
        """
        check_for_valid_session_tokens(resource)

if __name__ == "__main__":
    import fire
    fire.Fire(AzureMonitorCLI)
# Example usage:
#   python azure_monitor_logs_run_query.py run_query --workspace_id <id> --query "Your KQL here" --timespan "P1D" --output table
#   python azure_monitor_logs_run_query.py run_query --workspace_id <id> --query "Your KQL here" --timespan "P1D" --output json
#   python azure_monitor_logs_run_query.py token --resource "https://api.loganalytics.io" --show True
#   python azure_monitor_logs_run_query.py account
#   python azure_monitor_logs_run_query.py login --scope "https://api.loganalytics.io/.default"
#   python azure_monitor_logs_run_query.py check_session --resource "https://api.loganalytics.io"
# Note: Ensure 'azure-cli' is installed and 'az' command is available in PATH
