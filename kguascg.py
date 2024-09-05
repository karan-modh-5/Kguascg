import requests
import hashlib
import argparse
import sys
import re
import ipaddress
import warnings
import json  # Import the json module for pretty printing
from requests.packages.urllib3.exceptions import InsecureRequestWarning

version = "1.0.6"

# Initialize variables
ucm_ip = ""
ucm_port = ""
username = ""
password = ""

def is_valid_ip(ip):
    # Regular expression pattern for valid IPv4 addresses
    ip_pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return bool(ip_pattern.match(ip))  # Return True if valid, False otherwise

parser = argparse.ArgumentParser(description="karan's grandstream ucm api session cookie generator")
parser.add_argument("-v", action="store_true", help="Print version info")
parser.add_argument("-I", help="UCM IP Address")
parser.add_argument("-P", help="UCM Port Number")
parser.add_argument("-u", help="API Username")
parser.add_argument("-p", help="API User Password")

args = parser.parse_args()

if args.v:
    print("\nkguascg version: {}".format(version))
    sys.exit(0)

if args.I:
    if is_valid_ip(args.I):
        ucm_ip = args.I

if args.u:
    username = args.u

if args.p:
    password = args.p

if args.P:
    ucm_port = args.P

ERROR_RETURN_CODES = {
    0	: "Success",
    -1	: "Invalid parameters",
    -5	: "Need authentication",
    -6	: "Cookie error",
    -7	: "Connection closed",
    -8	: "System timeout",
    -9	: "Abnormal system error!",
    -15	: "Invalid value",
    -16	: "No such item. Please refresh the page and try again",
    -19	: "Unsupported",
    -24	: "Failed to operate data",
    -25	: "Failed to update data",
    -26	: "Failed to get data",
    -37	: "Wrong account or password!",
    -43	: "Some data in this page has been modified or deleted. Please refresh the page and try again",
    -44	: "This item has been added",
    -45	: "Operating too frequently or other users are doing the same operation. Please retry after 15 seconds.",
    -46	: "Operating too frequently or other users are doing the same operation. Please retry after 15 seconds.",
    -47	: "No permission",
    -50	: "Command contains sensitive characters",
    -51	: "Another task is running now",
    -57	: "Operating too frequently, or other users are doing the same operation. Please retry after 60 seconds",
    -68	: "Login Restriction",
    -69	: "There is currently a conference going on. Changes cannot be applied at this time",
    -70	: "Login Forbidden",
    -71	: "The username doesn't exist",
    -90	: "The conference is busy, cannot be edited or deleted",
    -98	: "There are currently digital calls. Failed to apply configuration",
}

# Suppress InsecureRequestWarning from urllib3
warnings.simplefilter('ignore', InsecureRequestWarning)

def get_challenge_response(ucm_ip, ucm_port, username, password):
    url = f"https://{ucm_ip}:{ucm_port}/api"
    payload = {
        "request": {
            "action": "challenge",
            "user": username,
            "version": "1.0"
        }
    }
    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Connection": "close"
    }

    print("request: ", payload)
    response = requests.post(url, json=payload, headers=headers, verify=False)
    print("Server response:", response.text)

    if response.status_code == 200:
        challenge = response.json().get("response", {}).get("challenge")
        status = response.json().get("status", {})
        print(ERROR_RETURN_CODES[int(status)])
        if challenge:
            md5_hash = hashlib.md5((challenge + password).encode()).hexdigest()
            return md5_hash
        else:
            raise ValueError("Challenge not received from server")
    else:
        raise ValueError(f"Error fetching challenge: {response.status_code} - {response.text}")

def login_with_token(ucm_ip, ucm_port, username, token):
    url = f"https://{ucm_ip}:{ucm_port}/api"
    payload = {
        "request": {
            "action": "login",
            "token": token,
            "user": username
        }
    }
    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Connection": "close"
    }

    print("request: ", payload)
    response = requests.post(url, json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        cookie = response.json().get("response", {}).get("cookie")
        status = response.json().get("status", {})
        print(ERROR_RETURN_CODES[int(status)])        
        if cookie:
            return cookie
        else:
            raise ValueError("Cookie not received from server")
    else:
        raise ValueError(f"Error fetching cookie: {response.status_code} - {response.text}")

def perform_action(ucm_ip, ucm_port, cookie, action, options=None):
    url = f"https://{ucm_ip}:{ucm_port}/api"
    payload = {
        "request": {
            "action": action,
            "cookie": cookie
        }
    }

    # Add any additional options provided by the user
    if options:
        payload["request"].update(options)

    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Connection": "close"
    }
    print("request: ", payload)
    response = requests.post(url, json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        status = response.json().get("status", {})
        print(ERROR_RETURN_CODES[int(status)])        
        return response.json()
    else:
        raise ValueError(f"Error performing action '{action}': {response.status_code} - {response.text}")

def additional_actions(ucm_ip, ucm_port, cookie):
    while True:
        action = input("\nEnter an action (e.g., 'getSystemStatus') or type 'exit' to quit: ").strip()
        if action.lower() == "exit":
            print("Exiting the script.")
            break
        if action.lower() == "quit":
            print("Exiting the script.")
            break

        options = {}

        # Check if specific mandatory options are needed
        if action.lower() == "cdrapi":
            format_option = input("Enter format (e.g., 'json' or 'xml' or 'csv'): ").strip()
            options["format"] = format_option
        if action.lower() == "pmsapi":
            format_option = input("Enter format (e.g., 'json' or 'xml' or 'csv'): ").strip()
            options["format"] = format_option

        # Ask user for additional options
        add_option = input("Do you want to add more options? (yes/no): ").strip().lower()
        while add_option == "yes":
            key = input("Enter option key (e.g., 'startTime'): ").strip()
            value = input("Enter option value (e.g., '2024-09-01T00:00'): ").strip()
            options[key] = value
            add_option = input("Do you want to add another option? (yes/no): ").strip().lower()

        try:
            result = perform_action(ucm_ip, ucm_port, cookie, action, options)
            # Pretty-print the JSON response
            print("Response:", json.dumps(result, indent=4))
        except Exception as e:
            print(f"Error: {str(e)}")

def main(ucm_ip, ucm_port, username, password):
    # Prompt for user input if not provided via arguments
    if not ucm_ip:
        ucm_ip = input("Enter the UCM IP address > ").strip()
    if not ucm_port:
        ucm_port = input("Enter SIP server port (e.g., 8089): ").strip() or "8089"
    if not username:
        username = input("Enter API username > ").strip()
    if not password:
        password = input("Enter API password > ").strip()

    try:
        # Fetch challenge response and login
        token = get_challenge_response(ucm_ip, ucm_port, username, password)
        cookie = login_with_token(ucm_ip, ucm_port, username, token)
        print("Login successful. Cookie:", cookie)

        # Get initial system status
        system_status = perform_action(ucm_ip, ucm_port, cookie, "getSystemStatus")
        # Pretty-print the JSON response for system status
        print("System Status:", json.dumps(system_status, indent=4))

        # Prompt for additional actions
        additional_actions(ucm_ip, ucm_port, cookie)

    except Exception as e:
        print(f"Error: {str(e)}")
try:
    if __name__ == "__main__":
        main(ucm_ip, ucm_port, username, password)
except:
    print("\nkguascg Stop Executing.")

finally:
    print("\n[kguascg_v{}]:".format(version))
