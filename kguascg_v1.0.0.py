import requests
import hashlib
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
warnings.simplefilter('ignore', InsecureRequestWarning)

def get_challenge_response(server_ip, server_port, username, password):
    url = f"https://{server_ip}:{server_port}/api"
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

def login_with_token(server_ip, server_port, username, token):
    url = f"https://{server_ip}:{server_port}/api"
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
    return response.json()  # Return the JSON response for further processing

def main():
    # Prompt user for SIP server details and credentials
    server_ip = input("Enter SIP server IP address: ")
    server_port = input("Enter SIP server port (e.g., 8089): ")
    username = input("Enter API username: ")
    password = input("Enter API password: ")

    try:
        # Fetch the challenge and generate the token
        token = get_challenge_response(server_ip, server_port, username, password)
        if token:
            # Perform login with the generated token
            response = login_with_token(server_ip, server_port, username, token)
            print("Login response:", response)  # Print the login response
        else:
            print("Failed to obtain token.")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
