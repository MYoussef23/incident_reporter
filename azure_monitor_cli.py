#!/usr/bin/env python3
"""
Azure Monitor CLI — merged utilities

Combines:
- Subscription & workspace selection (interactive) 
- Robust token acquisition with AADSTS50173 handling
- Log Analytics REST query execution
- Convenience commands (token/account/login/check_session)

Requires:
- Azure CLI ('az') installed and on PATH
- Python 'requests' and optional 'beep' module

Example:
  python azure_monitor_cli.py pick_workspace
  python azure_monitor_cli.py run_query --workspace_id "<guid>" --query "AzureActivity | take 1" --timespan "P1D" --output table
"""

import os
import sys
import csv
import json
import shutil
import subprocess
from typing import Optional, Tuple, List
import re
from pathlib import Path

# Optional beep helper
try:
    from beep import beep  # optional convenience
    _HAS_BEEP = True
except Exception:
    _HAS_BEEP = False

import warnings
from urllib3.exceptions import InsecureRequestWarning
warnings.simplefilter('ignore', InsecureRequestWarning)

import requests

AADSTS_NEEDS_INTERACTION = re.compile(r"(AADSTS50173|invalid_grant|interaction\s*required)", re.I)

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

def _maybe_beep():
    if _HAS_BEEP:
        try:
            beep()
        except Exception:
            pass

# ---------- Auth helpers (robust) ----------
def _az_login_interactive(tenant_id: Optional[str], scope: Optional[str] = None):
    """
    Perform an interactive login in the correct tenant.
    Uses device code on headless / terminal-only setups if desired.
    We keep standard 'az login' (browser) for simplicity; switch to --use-device-code if preferred.
    """
    cmd = [_az_exe(), "login"]
    if tenant_id:
        cmd += ["--tenant", tenant_id]
    if scope:
        cmd += ["--scope", scope]
    subprocess.run(cmd, check=True)

def get_access_token_once(resource: str, tenant_id: Optional[str] = None) -> Tuple[Optional[str], str]:
    """
    Try to get a token ONCE. Returns (token_or_None, raw_output_text).
    We capture stderr because az often writes error details there.
    """
    try:
        out = subprocess.run(
            [_az_exe(), "account", "get-access-token", "--resource", resource, "--tenant", tenant_id, "--query", "accessToken", "-o", "tsv"],
            check=True, capture_output=True, text=True
        )
        return out.stdout.strip(), (out.stderr or "")
    except subprocess.CalledProcessError as e:
        text = (e.stdout or "") + (e.stderr or "")
        return None, text

def ensure_access_token(resource: str, tenant_id: Optional[str] = None, scope_for_login: Optional[str] = None) -> str:
    """
    Get a token for 'resource'. If AADSTS50173/invalid_grant/interaction required is detected,
    do an interactive login (in the given tenant) and retry once.
    """
    token, txt = get_access_token_once(resource, tenant_id=tenant_id)
    if token:
        return token

    if AADSTS_NEEDS_INTERACTION.search(txt):
        print("Detected AADSTS50173/invalid_grant. Performing interactive login...")
        # Helpful to first log into management scope so subs/tenants enumerate correctly
        mgmt_scope = "https://management.core.windows.net//.default"
        try:
            _az_login_interactive(tenant_id=tenant_id, scope=mgmt_scope)
        except subprocess.CalledProcessError:
            # ignore if not supported in environment; continue
            pass
        _az_login_interactive(tenant_id=tenant_id, scope=scope_for_login or (resource + "/.default"))
        token, txt2 = get_access_token_once(resource, tenant_id=tenant_id)
        if token:
            return token
        raise RuntimeError(f"Auth still failing after interactive login:\n{txt2}")

    # Some other failure
    raise RuntimeError(f"Failed to retrieve access token for {resource}.\n{txt}")

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

# ---------- Subscription & Workspace selection ----------
def get_current_subscription() -> Optional[dict]:
    try:
        output = subprocess.check_output([_az_exe(), "account", "show", "-o", "json"], text=True)
        account = json.loads(output)    # This gets the current subscription
        return account
    except Exception as e:
        print(f"Could not retrieve current subscription: {e}")
        return None

def prompt_change_subscription(current_sub: dict) -> bool:
    print(f"\nCurrent Subscription: {current_sub.get('name')}")
    print(f"Subscription ID: {current_sub.get('id')}")
    while True:
        _maybe_beep()
        answer = input("Do you want to continue using this subscription? (Y/N): ").strip().lower()
        if answer in ('y', 'yes', 'n', 'no'):
            return answer in ('y', 'yes')
        else:
            print("Please enter 'y' for yes or 'n' for no.")

def list_and_select_subscription(account_name: str) -> Optional[dict]:
    try:
        output = subprocess.check_output([_az_exe(), "account", "list", "-o", "json"], text=True)
        subs = json.loads(output)

        # Filter subscriptions by current account username
        filtered_subs = [
            sub for sub in subs
            if sub.get('user', {}).get('name', '').lower() == (account_name or "").lower()
        ]

        if not filtered_subs:
            print(f"No subscriptions found for account '{account_name}'.")
            return None

        print(f"\nAvailable subscriptions for {account_name}:")
        for i, sub in enumerate(filtered_subs, 1):
            print(f"{i}: {sub['name']} ({sub['id']})")

        while True:
            _maybe_beep()
            idx_input = input("Enter the number for the subscription to switch to: ").strip()
            if not idx_input.isdigit():
                print("Please enter a valid number.")
                continue

            idx = int(idx_input) - 1
            if 0 <= idx < len(filtered_subs):
                break
            else:
                print("Selection out of range. Try again.")

        new_sub_id = filtered_subs[idx]['id']
        # Set new subscription
        subprocess.run([_az_exe(), "account", "set", "--subscription", new_sub_id], check=True)
        print(f"Switched to subscription: {filtered_subs[idx]['name']}")
        return filtered_subs[idx]
    except Exception as e:
        print(f"Error listing/subscribing: {e}")
        return None

def list_and_select_workspace(current_sub_id: str) -> Optional[str]:
    """
    List all Log Analytics workspaces in the subscription and allow the user to select one.
    Returns the workspace 'customerId' (Workspace ID / GUID).
    """
    try:
        output = subprocess.check_output(
            [_az_exe(), "monitor", "log-analytics", "workspace", "list",
             "--subscription", current_sub_id, "-o", "json"],
            text=True
        )
        wss = json.loads(output)
    except subprocess.CalledProcessError as e:
        print(f"Failed to list workspaces: {e.output}")
        return None

    if not wss:
        print("No workspaces found for this subscription.")
        return None

    # If only one workspace, auto-select
    if len(wss) == 1:
        ws = wss[0]
        print("="*50)
        print(f"Only one workspace found and automatically selected: {ws.get('name', 'Unknown')} | Customer ID: {ws.get('customerId', 'N/A')}")
        print("="*50)
        return ws.get("customerId")

    print("\nAvailable Workspaces:")
    for i, ws in enumerate(wss):
        print(f"{i + 1}: Workspace Name: {ws.get('name', 'Unknown')} | Customer ID: {ws.get('customerId', 'N/A')}")
    while True:
        _maybe_beep()
        idx = input("Enter the number of the workspace to use: ").strip()
        try:
            idx = int(idx) - 1
            if 0 <= idx < len(wss):
                break
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")

    new_ws_id = wss[idx].get("customerId")
    print(f"Selected Workspace ID: {new_ws_id} ({wss[idx].get('name')})")
    return new_ws_id

def azure_monitor_login(tenant_id: Optional[str] = None) -> Optional[str]:
    """
    Ensure the user is authenticated and select a subscription and workspace.
    Returns a workspace_id (customerId) or None.
    """

    if tenant_id:
        # Validate auth for management (subs list requires mgmt audience)
        mgmt_resource = "https://management.core.windows.net/"
        try:
            ensure_access_token(mgmt_resource, tenant_id=tenant_id, scope_for_login="https://management.core.windows.net//.default")
            # get tenant from current account
            output = subprocess.check_output([_az_exe(), "account", "show", "-o", "json"], text=True)
            account_info = json.loads(output)
            tenant_id = account_info.get("tenantId")
            tenant_name = account_info.get("user", {}).get("name", "Unknown")
            print(f"Session token for {mgmt_resource} is valid for tenant {tenant_id} (Account: {tenant_name}).")
        except Exception as e:
            print(f"Auth check failed for {mgmt_resource}: {e}")
            return None
    else:
        # Log in without tenant (default)
        try:
            _az_login_interactive(tenant_id=None, scope="https://management.core.windows.net//.default")
            # get tenant from current account
            output = subprocess.check_output([_az_exe(), "account", "show", "-o", "json"], text=True)
            account_info = json.loads(output)
            tenant_id = account_info.get("tenantId")
            tenant_name = account_info.get("user", {}).get("name", "Unknown")
            print(f"Logged in to tenant: {tenant_id} (Account: {tenant_name}).")
        except Exception as e:
            print(f"Login failed: {e}")
            return None
            
    # Current subscription (may be None if not set)
    current_sub = get_current_subscription()
    if current_sub:
        if not prompt_change_subscription(current_sub):
            current_account = get_azure_account_name()
            new_sub = list_and_select_subscription(account_name=current_account or "", tenant_id=tenant_id)
            if new_sub:
                current_sub = new_sub
        current_sub_id = current_sub['id']
        print(f"Continuing with subscription: {current_sub['name']} ({current_sub_id})")
    else:
        # No current sub; force user to pick one
        current_account = get_azure_account_name() or ""
        current_sub = list_and_select_subscription(account_name=current_account)
        if not current_sub:
            print("No subscription selected.")
            return None
        current_sub_id = current_sub['id']

    print(f"Subscription ID: {current_sub_id}")

    # Workspace selection
    workspace_id = list_and_select_workspace(current_sub_id=current_sub_id)
    if not workspace_id:
        print("No workspace selected.")
        return None

    print("\nAzure login + workspace selection complete.")
    return workspace_id, tenant_id

# ---------- Log Analytics query ----------
def _load_query_text(q: str) -> str:
    if q == "-":
        return sys.stdin.read()
    if q.startswith("@"):
        return Path(q[1:]).read_text(encoding="utf-8")
    p = Path(q)
    if p.exists() and p.is_file():
        return p.read_text(encoding="utf-8")
    return q

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

def _query_log_analytics(query: str, timespan: str, verify_tls: bool, tenant_id: Optional[str] = None, workspace_id: Optional[str] = None) -> dict:
    """
    Calls the Log Analytics Query REST API and returns the JSON payload (dict).
    Will auto-trigger interactive auth on AADSTS50173 both during token fetch and on HTTP 401.
    """
    resource = "https://api.loganalytics.io"
    scope = f"{resource}/.default"
    
    token = ensure_access_token(resource, tenant_id=tenant_id, scope_for_login=scope)

    url = f"{resource}/v1/workspaces/{workspace_id}/query"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = {"query": query, "timespan": timespan}

    resp = requests.post(url, headers=headers, json=body, verify=verify_tls)
    if resp.status_code == 200:
        return resp.json()

    # If token was valid when acquired but now rejected (e.g., mid-run policy change),
    # detect interaction-required and force a re-login, then retry once.
    if resp.status_code in (401, 403) and AADSTS_NEEDS_INTERACTION.search(resp.text or ""):
        print("Server indicated interaction is required (e.g., AADSTS50173). Re-authenticating...")
        _az_login_interactive(tenant_id=tenant_id, scope=scope)
        token = ensure_access_token(resource, tenant_id=tenant_id, scope_for_login=scope)
        headers["Authorization"] = f"Bearer {token}"
        resp = requests.post(url, headers=headers, json=body, verify=verify_tls)
        if resp.status_code == 200:
            return resp.json()

    raise RuntimeError(f"Error querying Log Analytics: {resp.status_code} {resp.text}")

# ---------- Python Fire CLI ----------
class AzureMonitorCLI:
    """
    Azure Log Analytics (Sentinel) helper CLI.

    Commands:
      pick_workspace      Interactive login + subscription/workspace selection; prints workspace ID.
      run_query           Run a KQL query against a Log Analytics workspace.
      token               Acquire/validate a token for a resource; optionally print it.
      account             Show current Azure CLI account name.
      login               Trigger interactive az login with optional tenant/scope.
      check_session       Validate/refresh session for a resource.
    """

    # --- Workspace selection ---
    def pick_workspace(self, tenant_id: Optional[str] = None):
        ws = azure_monitor_login(tenant_id=tenant_id)
        if ws:
            print(f"Workspace ID: {ws}")
        else:
            print("Workspace selection was not completed.")

    # --- Run query ---
    def run_query(
        self,
        workspace_id: str,
        query: str,
        timespan: str,
        output: str = "table",
        csv_path: Optional[str] = None,
        sep: str = " | ",
        verify_tls: bool = True,
        tenant_id: Optional[str] = None,
    ):
        """
        Run a KQL query.

        Args:
          workspace_id: Log Analytics Workspace ID (GUID).
          query:        KQL query string or @file.txt or '-' (stdin).
          timespan:     ISO8601 timespan (e.g., 'P1D') or 'YYYY-MM-DDTHH:MM:SSZ/YYYY-MM-DDTHH:MM:SSZ'.
          output:       'table' (default), 'json', or 'csv'.
          csv_path:     If provided (or output='csv'), write CSV to this path.
          sep:          Column separator for 'table' rendering.
          verify_tls:   Verify TLS certs for HTTPS requests (default True).
          tenant_id:    Optional tenant ID for targeted authentication.
        """
        query = _load_query_text(query)
        result = _query_log_analytics(workspace_id, query, timespan, verify_tls=verify_tls, tenant_id=tenant_id)
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

    # --- Token / session utilities ---
    def token(self, resource: str = "https://api.loganalytics.io", show: bool = False, tenant_id: Optional[str] = None):
        """
        Acquire and validate an access token for a resource. 
        Will auto-handle AADSTS50173/invalid_grant by forcing interactive login.

        Args:
          resource:  Azure resource audience (default: Log Analytics API).
          show:      If True, prints the raw access token (handle with care).
          tenant_id: Optional tenant ID to enforce login in the correct directory.
        """
        try:
            tok = ensure_access_token(resource, tenant_id=tenant_id, scope_for_login=f"{resource}/.default")
            print(f"Token valid for {resource}: True")
            if show:
                print(tok or "")
        except Exception as e:
            print(f"Token valid for {resource}: False")
            print(f"Details: {e}")

    def account(self):
        """
        Print current Azure CLI account user.name.
        """
        acct = get_azure_account_name()
        print(acct or "Unknown")

    def login(self, tenant_id: Optional[str] = None, scope: str = "https://api.loganalytics.io/.default"):
        """
        Run 'az login' with the provided scope (and optional tenant).
        """
        _az_login_interactive(tenant_id=tenant_id, scope=scope)
        print("Login completed.")

    def check_session(self, resource: str = "https://api.loganalytics.io", tenant_id: Optional[str] = None):
        """
        Validate current session/token for a resource.
        Automatically handles AADSTS50173/invalid_grant by forcing interactive login if needed.
        """
        try:
            _ = ensure_access_token(resource, tenant_id=tenant_id, scope_for_login=f"{resource}/.default")
            print(f"Session token for {resource} is valid.")
            acct = get_azure_account_name()
            if acct:
                print(f"Current Azure account: {acct}")
        except Exception as e:
            print(f"Session token for {resource} is invalid or expired.")
            print(f"Details: {e}")

if __name__ == "__main__":
    import fire
    fire.Fire(AzureMonitorCLI)
