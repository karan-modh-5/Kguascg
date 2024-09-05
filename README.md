# SIP Server API Interaction Script

This Python script interacts with a SIP server API to perform authentication and retrieve system status information. It uses HTTP POST requests to authenticate via a challenge-response mechanism and then obtains a session cookie to execute further API commands.

## Features

- **Challenge-Response Authentication**: The script requests a challenge from the SIP server and generates an MD5 hash using the challenge and user password.
- **Session Cookie Management**: After successful authentication, the script stores the session cookie for further API interactions.
- **System Status Retrieval**: The script fetches the system status using the authenticated session.
- **IP Address Validation**: Checks for valid IPv4 addresses and prevents using a subnet mask.
- **Command-line Argument Support**: Supports command-line arguments for IP address, username, and password.

## Prerequisites

- Python 3.x
- `requests` library
  - Install using pip: 
    ```sh
    pip install requests
    ```

## Usage

1. **Clone the Repository**

   ```sh
   git clone https://github.com/karan-modh-5/Kguascg.git
   cd Kguascg

2. **Run the Script**

Execute the Python script from your terminal or command prompt:

    python kguascg.py -i <UCM IP> -u <API Username> -p <API Password>
Alternatively, you can run without command-line arguments and provide inputs interactively.

3. **Provide Input Details**

The script will prompt for the following details if not provided via command-line arguments:

- UCM IP Address: The IP address of your SIP server.
- API Username: Your API user name.
- API Password: Your API password.

4. View Output

The script will display:

- The server response for the authentication challenge.
- The authentication token and session cookie.
- The system status information retrieved from the server.

### New Features in Version 1.0.6

1. **Error Return Codes Dictionary**
   - A dictionary `ERROR_RETURN_CODES` has been added to map server response status codes to human-readable error messages. This provides more meaningful feedback when errors occur.
   - Example:
     ```python
     ERROR_RETURN_CODES = {
         0   : "Success",
         -1  : "Invalid parameters",
         -5  : "Need authentication",
         ...
     }
     ```

2. **Formatted JSON Output**
   - Integrated JSON pretty-printing using `json.dumps` to display server responses in a human-readable format.
   - Example:
     ```python
     print("Response:", json.dumps(result, indent=4))
     ```

3. **Enhanced User Input for Additional Options**
   - The script now allows users to input multiple options dynamically for various actions. For example, when the user inputs "cdrapi", it prompts for the required "format" option and allows additional options to be added interactively.

4. **Specific Handling for Certain Actions**
   - Custom prompts are added for specific actions like `"cdrapi"` or `"pmsapi"` where certain mandatory options (such as `"format"`) are required.

5. **Improved User Experience for Exiting**
   - Added flexibility for exiting the script by typing "quit" or "exit".

6. **Enhanced Logging of Requests and Server Responses**
   - The script now logs request payloads and server responses to provide transparency and assist in debugging.
   - Example:
     ```python
     print("request: ", payload)
     print("Server response:", response.text)
     ```

### Changes

1. **Version Number Update**
   - Updated from `1.0.3` to `1.0.6` to reflect new changes and features.

2. **Incorporation of `ERROR_RETURN_CODES` in Responses**
   - Uses `ERROR_RETURN_CODES` to display a user-friendly error message corresponding to the API's numeric status code.
   - Example:
     ```python
     status = response.json().get("status", {})
     print(ERROR_RETURN_CODES[int(status)])
     ```

3. **Error Handling Enhancements**
   - Improved error handling to provide more descriptive messages based on server responses.

4. **Refactored `perform_action` Function**
   - The function now accepts dynamic additional options (`options` parameter) to be passed into the request payload.
   - Example:
     ```python
     if options:
         payload["request"].update(options)
     ```

### Usage

To run the script, use the following command:

  ```bash
    python kguascg.py -I <UCM IP Address> -P <UCM Port Number> -u <API Username> -p <API Password>
  ```

### Example
Here is an example of how the script might be executed:

    python kguascg.py -i 192.168.43.160 -u cdrapi -p cdrapi123
If run interactively:

    Enter SIP server IP address: 192.168.43.160
    Enter API username: cdrapi
    Enter API password: cdrapi123
    Login successful. Cookie: abc12345
    System Status: {"status": "ok", "uptime": "12345 seconds"}
### Script Details
- get_challenge_response: Fetches the challenge from the server and generates an MD5 token.
- login_with_token: Logs in using the generated token and retrieves a session cookie.
- get_system_status: Uses the session cookie to fetch the system status from the server.
- IP and Subnet Validation: Validates the provided IP address and checks against invalid subnet masks.

### Handling HTTPS Warnings
The script uses an InsecureRequestWarning suppression to handle unverified HTTPS requests. This is required when the SIP server uses a self-signed SSL certificate.

Note: For production use, consider verifying SSL certificates to ensure secure communication.

### Troubleshooting
- Ensure that the SIP server is running and accessible via the provided IP address and port.
- Check that the API username and password are correct.
- If you encounter a "Challenge not received from server" error, verify that the server is correctly configured to provide the challenge response.

### Contributing
Feel free to submit issues or fork the repository and contribute via pull requests. Contributions are welcome!

### Acknowledgements
Requests Library for simplifying HTTP requests in Python.
Inspiration from other SIP API scripts and tools.
