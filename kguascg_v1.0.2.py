import requests
import hashlib
import argparse
import sys
import re
import ipaddress
import os
import math
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

version = "1.0.2"

# undefined start point
ucm_ip = ""
username = ""
password = ""

def is_valid_ip(ip):
    # Regular expression pattern for valid IPv4 addresses
    ip_pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return bool(ip_pattern.match(ip))  # Return True if valid, False otherwise

def is_valid_subnet_mask(subnet_mask):
    try:
        # Parse the subnet mask
        subnet = ipaddress.IPv4Network(f"0.0.0.0/{subnet_mask}", strict=False)
        return not subnet.with_prefixlen.endswith('/0')
    except ValueError:
        return False

parser = argparse.ArgumentParser(description="karan's grandstream ucm api session cookie generator")
parser.add_argument("-v", action="store_true", help="Print version info")
parser.add_argument("-i", help="UCM IP Address")
parser.add_argument("-u", help="API Username")
parser.add_argument("-p", help="API Useer Password")

args = parser.parse_args()

if args.v:
    print("\nkguascg version: {}".format(version))
    sys.exit(0)

if args.i:
    if is_valid_ip(args.i):
        ucm_ip = args.i
        
if args.u:
    username = args.u
        
if args.p:
    password = args.p
        
# Suppress only the single InsecureRequestWarning from urllib3
warnings.simplefilter('ignore', InsecureRequestWarning)

def get_challenge_response(ucm_ip, username, password):
    url = f"https://{ucm_ip}:8089/api"
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
    
    # Make the POST request to get the challenge
    response = requests.post(url, json=payload, headers=headers, verify=False)
    
    # Print the server response for debugging
    print("Server response:", response.text)
    
    if response.status_code == 200:
        # Attempt to extract the challenge from the response
        challenge = response.json().get("response", {}).get("challenge")
        if challenge:
            # Generate the MD5 hash using the challenge and password
            md5_hash = hashlib.md5((challenge + password).encode()).hexdigest()
            return md5_hash
        else:
            raise ValueError("Challenge not received from server")
    else:
        raise ValueError(f"Error fetching challenge: {response.status_code} - {response.text}")

def login_with_token(ucm_ip, username, token):
    url = f"https://{ucm_ip}:8089/api"
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
    
    # Make the POST request to login with the token
    response = requests.post(url, json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        # Extract the cookie from the response
        cookie = response.json().get("response", {}).get("cookie")
        if cookie:
            return cookie
        else:
            raise ValueError("Cookie not received from server")
    else:
        raise ValueError(f"Error fetching cookie: {response.status_code} - {response.text}")

def get_system_status(ucm_ip, cookie):
    url = f"https://{ucm_ip}:8089/api"
    payload = {
        "request": {
            "action": "getSystemStatus",
            "cookie": cookie
        }
    }
    headers = {
        "Content-Type": "application/json;charset=UTF-8",
        "Connection": "close"
    }
    
    # Make the POST request to get system status
    response = requests.post(url, json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        return response.json()  # Return the JSON response for further processing
    else:
        raise ValueError(f"Error fetching system status: {response.status_code} - {response.text}")

def main(ucm_ip, username, password):
    # Prompt user for SIP server details and credentials
    if ucm_ip == "":
        while True:
            ucm_ip = input("Enter the UCM IP address >")
            if is_valid_ip(ucm_ip):
                if is_valid_subnet_mask(ucm_ip):
                    print("Entered value is Subnet Mask not IP Addresss")
                    continue
                else:
                    break
            else:
                print("Invalid IP address. Please enter a valid IPv4 address.")
                
    if username == "":
        username = input("Enter API username: ")
    if password == "":
        password = input("Enter API password: ")

    try:
        # Fetch the challenge and generate the token
        token = get_challenge_response(ucm_ip, username, password)
        if token:
            # Perform login with the generated token
            cookie = login_with_token(ucm_ip, username, token)
            print("Login successful. Cookie:", cookie)  # Print the cookie

            # Use the cookie to get the system status
            system_status = get_system_status(ucm_ip, cookie)
            print("System Status:", system_status)
        else:
            print("Failed to obtain token.")
    except Exception as e:
        print(f"Error: {str(e)}")
try: 
    if __name__ == "__main__":
        main(ucm_ip, username, password)
except:
    print("\nkguascg Stop Executing.")

finally:
    print("\n[kguascg_v{}]:".format(version))