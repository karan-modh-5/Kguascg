import requests
import hashlib
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
warnings.simplefilter('ignore', InsecureRequestWarning)

def get_challenge_response(server_ip, username, password):
    url = f"https://{server_ip}:8089/api"
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

def login_with_token(server_ip, username, token):
    url = f"https://{server_ip}:8089/api"
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

def get_system_status(server_ip, cookie):
    url = f"https://{server_ip}:8089/api"
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

def main():
    # Prompt user for SIP server details and credentials
    server_ip = input("Enter SIP server IP address: ")
    username = input("Enter API username: ")
    password = input("Enter API password: ")

    try:
        # Fetch the challenge and generate the token
        token = get_challenge_response(server_ip, username, password)
        if token:
            # Perform login with the generated token
            cookie = login_with_token(server_ip, username, token)
            print("Login successful. Cookie:", cookie)  # Print the cookie

            # Use the cookie to get the system status
            system_status = get_system_status(server_ip, cookie)
            print("System Status:", system_status)
        else:
            print("Failed to obtain token.")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
