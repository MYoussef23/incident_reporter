import subprocess
import requests
import argparse
import beep

# Function to get the detection query results from Azure Sentinel
def run_query(workspace_id, query, timespan):
    """
    Query Azure Log Analytics via REST API
    """
    
    if is_token_valid("https://api.loganalytics.io"):
        token = get_access_token("https://api.loganalytics.io")
    else:
        check_for_valid_session_tokens("https://api.loganalytics.io")   # Check for valid session tokens in https://api.loganalytics.io - which is necessary to run queries in Sentinel.
        token = get_access_token("https://api.loganalytics.io")

    url = f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    # Adjust the KQL query as needed for your Sentinel schema
    body = {
        "query": query,
        "timespan": timespan
    }
    response = requests.post(url, headers=headers, json=body, verify=False)
    if response.status_code != 200:
        return f"Error querying Log Analytics: {response.status_code} {response.text}"
    result = response.json()
    
    # output the result to HTML format with each line separated by '<br />'
    tables = result.get("tables", [])
    if not tables:
        return "No data returned from the query."

    table = tables[0]
    return table

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
        return False
    except requests.RequestException as e:
        return False
    
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

def prompt_change_account(account):
    print(f"Current Azure account: {account}")
    while True:
        beep.beep()     # Play a notification sound for user attention
        answer = input("Do you want to continue using this account? (Y/N): ").strip().lower()
        if answer in ('y', 'yes', 'n', 'no'):
            return answer in ('y', 'yes')
        else:
            beep.beep()     # Play a notification sound for user attention
            print("Please enter 'y' for yes or 'n' for no.")

def Azure_scope_login(scope):
    subprocess.run([
        r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd",
        "login",
        "--scope", scope
    ], check=True)      # This will open a browser window to enter credentials.

def main():
    parser = argparse.ArgumentParser(description="Query Azure Log Analytics via REST API")
    parser.add_argument("--workspace-id", required=True, help="Azure Log Analytics Workspace ID")
    parser.add_argument("--query", required=True, help="KQL query to run")
    parser.add_argument("--timespan", required=True, help="Timespan for the query (e.g. 'P1D' or 'YYYY-MM-DDT00:00:00Z/YYYY-MM-DDT00:00:00Z')")
    args = parser.parse_args()

    # Run the query
    table = run_query(args.workspace_id, args.query, args.timespan)
    if table:
        # Print columns and rows in readable format
        columns = [col['name'] for col in table['columns']]
        print(" | ".join(columns))
        print("-" * 60)
        for row in table['rows']:
            print(" | ".join(str(cell) for cell in row))
    
if __name__ == '__main__':
   main()