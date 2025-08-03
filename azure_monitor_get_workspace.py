import os
import subprocess
import json
import requests

def azure_monitor_login():
    print("\nWelcome to the Azure Monitor Logs Query Tool!")
    print("This tool will help you run queries against Azure Monitor Logs to retrieve incident details.")
    print("You will need to login to Azure and select the subscription and workspace you want to use.")
    
    # Start the Azure login process
    # This will open a browser window for the user to login to Azure and get the workspace ID. 
    check_for_azure_cli_installation()  # Ensure Azure CLI is installed
    print("\nLogging in to Azure...")

    check_for_valid_session_tokens("https://management.core.windows.net/")    # Check for valid session tokens in https://management.core.windows.net/ - which is necessary to fetch current accounts and subscriptons. 

    # Notify user of subscription selection and ask if a change is needed
    current_sub = get_current_subscription()
    if current_sub:
        if not prompt_change_subscription(current_sub):
            current_account = get_azure_account_name()
            new_sub = list_and_select_subscription(current_account)
            if new_sub:
                current_sub = new_sub
        current_sub_id = current_sub['id']
        print(f"Continuing with subscription: {current_sub['name']} ({current_sub_id})")

    print(f"Subscription ID: {current_sub_id}")

    # Get the list of Log Analytics workspaces in the subscription and allow user to select
    workspace_id = list_and_select_workspace(current_sub_id)
    
    print("\nAzure login successful.")

    return workspace_id

def check_for_azure_cli_installation():
    # Ensure the Azure CLI is installed and available
    if not os.path.exists(r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"):
        # install the Azure CLI by running 'winget install --exact --id Microsoft.AzureCLI' in a PowerShell terminal.
        subprocess.run(["winget", "install", "--exact", "--id", "Microsoft.AzureCLI"], check=True)
        print("Azure CLI installed successfully.")

def check_for_valid_session_tokens(resource):
    # Check if the user is already logged in to Azure
    if is_token_valid(resource):
        print(f"Session token for {resource} is still valid.")
        # Check for current account (user) name associated with the current Azure CLI session token
        account = get_azure_account_name()
        if account:
            continue_with_account = prompt_change_account(account)
            if not continue_with_account:
                print("Please login with a different account.")
                # Login to Azure CLI and set the scope for Azure
                Azure_scope_login(resource + '/.default')
            else:
                print("Continuing with current account.")
    else:
        # If the token is invalid or expired, prompt the user to login again
        print(f"Session token for {resource} is invalid or expired. Please login again.")
        # Login to Azure CLI and set the scope for Azure
        Azure_scope_login(resource + '/.default')

def get_current_subscription():
    try:
        output = subprocess.check_output([
            r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
            "account", "show", "-o", "json"
        ], text=True)
        account = json.loads(output)    # This gets the current subscription
        return account
    except Exception as e:
        print(f"Could not retrieve current subscription: {e}")
        return None
    
def prompt_change_subscription(current_sub):
    print(f"\nCurrent Subscription: {current_sub['name']}")
    print(f"Subscription ID: {current_sub['id']}")
    while True:
        answer = input("Do you want to continue using this subscription? (Y/N): ").strip().lower()
        if answer in ('y', 'yes', 'n', 'no'):
            return answer in ('y', 'yes')
        else:
            print("Please enter 'y' for yes or 'n' for no.")

def get_azure_account_name():
    try:
        account_name = subprocess.check_output(
            [
                r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
                "account", "show",
                "--query", "user.name",
                "-o", "tsv"
            ],
            text=True       # This gets the current account name
        ).strip()
        return account_name
    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve account name: {e.output}")
        return None
    
def list_and_select_subscription(account_name):
    try:
        output = subprocess.check_output([
            r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
            "account", "list", "-o", "json"
        ], text=True)
        subs = json.loads(output)

        # Filter subscriptions by current account username
        filtered_subs = [
            sub for sub in subs
            if sub.get('user', {}).get('name', '').lower() == account_name.lower()
        ]

        if not filtered_subs:
            print(f"No subscriptions found for account '{account_name}'.")
            return None

        print(f"\nAvailable subscriptions for {account_name}:")
        for i, sub in enumerate(filtered_subs, 1):
            print(f"{i}: {sub['name']} ({sub['id']})")

        while True:
            idx_input = input("Enter the number for the subscription to switch to: ").strip()
            if not idx_input.isdigit():
                print("Please enter a valid number.")
                continue

            idx = int(idx_input) - 1
            if 0 <= idx < len(subs):
                break
            else:
                print("Selection out of range. Try again.")

        # new_sub_id = subs[idx]['id']
        new_sub_id = filtered_subs[idx]['id']
        # Set new subscription
        subprocess.run([
            r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
            "account", "set", "--subscription", new_sub_id
        ], check=True)
        print(f"Switched to subscription: {subs[idx]['name']}")
        return subs[idx]
    except Exception as e:
        print(f"Error listing/subscribing: {e}")
        return None
    
def list_and_select_workspace(current_sub_id):  # This will list all the workspaces available in the subscription and allow the user to select the required workspace
    output = subprocess.check_output(
        [
            r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
            "monitor", "log-analytics", "workspace", "list",
            "--subscription", current_sub_id,
            "-o", "json"
        ],
        text=True)
    wss = json.loads(output)
    
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
        idx = input("Enter the number of the workspace to use: ")
        try:
            idx = int(idx) - 1
            if 0 <= idx < len(wss):
                break
            else:
                print("Invalid selection. Try again.")
        except ValueError:
            print("Please enter a valid number.")
    # Set new workspace
    new_ws_id = wss[idx].get("customerId")
    print(f"Selected Workspace ID: {new_ws_id} ({wss[idx].get('name')})")
    return new_ws_id

def is_token_valid(resource):
    try:
        token = get_access_token(resource)

        # Make a harmless request to test token validity
        headers = {
            "Authorization": f"Bearer {token}"
        }
        test_url = "https://management.azure.com/"
        response = requests.get(test_url, headers=headers, timeout=5)

        # Return True only if token is accepted
        if response.status_code != 400:
            print(f"Token for {resource} is invalid (status {response.status_code})")
            return False
        elif token == None:
           return False 
        return True
    except subprocess.CalledProcessError as e:
        #print(f"Access token retrieval failed for {resource}. Output:\n{e.output}")
        return False
    except requests.RequestException as e:
        #print(f"Request failed during token validation for {resource}: {e}")
        return False

def prompt_change_account(account):
    print(f"Current Azure account: {account}")
    while True:
        answer = input("Do you want to continue using this account? (Y/N): ").strip().lower()
        if answer in ('y', 'yes', 'n', 'no'):
            return answer in ('y', 'yes')
        else:
            print("Please enter 'y' for yes or 'n' for no.")

def Azure_scope_login(scope):
    subprocess.run([
        r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
        "login",
        "--scope", scope
    ], check=True)      # This will open a browser window to enter credentials.

def get_access_token(resource):
    try:
        access_token = subprocess.check_output([
                r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
                "account", "get-access-token",
                "--resource", resource,
                "--query", "accessToken",
                "-o", "tsv"
            ], text=True).strip()       # This gets the access token for the Azure resource
        return access_token
    except subprocess.CalledProcessError as e:
        print(f"Failed to retrieve access token for {resource}. Details:\n{e.output}")
        return None
    
if __name__ == "__main__":
    # Run the Azure Monitor login function to get the workspace ID
    azure_monitor_login()