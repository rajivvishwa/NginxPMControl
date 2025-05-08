import requests
import os
import logging
from dotenv import load_dotenv
import pandas as pd
import keyring
from keyring.errors import PasswordDeleteError
from rich.console import Console
from rich.table import Table

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
KEYRING_SERVICE = "pihole-auth"

def pihole_auth(pihole_server, pihole_password):
    """
    Authenticate with the Pi-hole server using the API key.
    """
    url = f'https://{pihole_server}/api/auth'
    payload = {"password": pihole_password}

    # Disable SSL warnings for self-signed certificates
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    # Send POST request to authenticate
    try:
        response = requests.post(url, json=payload, verify=False)
        response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
        logging.info("Authentication successful.")
        token = response.json()
        sid = token['session']['sid']
        if not sid:
            logging.error("Failed to retrieve session ID.")
            return None
        else:
            logging.info("Session ID retrieved successfully.")
        return token
    except requests.exceptions.RequestException as e:
        logging.error(f"Authentication failed: {e}")
        return None

def put_token_keyring(token):
    """Store the token in the system keyring."""
    sid = token['session']['sid']
    csrf = token['session']['csrf']
    try:
        keyring.delete_password(KEYRING_SERVICE, "sid")
        keyring.delete_password(KEYRING_SERVICE, "csrf")
    except PasswordDeleteError:
        pass  # Ignore if the password doesn't exist yet

    keyring.set_password(KEYRING_SERVICE, "sid", sid)
    keyring.set_password(KEYRING_SERVICE, "csrf", csrf)

    # Store the token in the keyring
    print("Token stored in keyring successfully.")

def get_token_keyring():
    """Retrieve the token from the system keyring."""
    try:
        sid = keyring.get_password(KEYRING_SERVICE, "sid")
        csrf = keyring.get_password(KEYRING_SERVICE, "csrf")
        return sid, csrf
    except keyring.errors.KeyringError as e:
        logging.error(f"Error retrieving token from keyring: {e}")
        return None

def get_valid_token():
    """
    Retrieve a valid token from the keyring or fetch a new one if not available.
    """ 
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
    pihole_server = os.getenv("PIHOLE_SERVER")
    pihole_password = os.getenv("PIHOLE_PASSWORD")

    if not pihole_server or not pihole_password:
        logging.error("Please set the PIHOLE_SERVER and PIHOLE_PASSWORD environment variables.")
    else:
        logging.info("Loaded environment variables successfully.")
    sid, csrf = get_token_keyring()

    if not sid or not csrf:
        logging.error("Failed to retrieve session ID or CSRF token from keyring.")
        token = pihole_auth(pihole_server, pihole_password)
        if not token:
            logging.error("Failed to authenticate with Pi-hole server.")
            return
        # Store the token in the keyring
        put_token_keyring(token)
    else:
        logging.info("Checking if the token is valid...")
        logging.info(f"Session ID: {sid}")
        logging.info(f"CSRF Token: {csrf}")

        # Check if the token is valid
        url = f'https://{pihole_server}/api/auth'
        payload = {}
        headers = {
        "X-FTL-SID": sid,
        "X-FTL-CSRF": csrf
        }

        # Disable SSL warnings for self-signed certificates
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        # Send POST request to authenticate
        try:
            response = requests.request("GET", url, headers=headers, data=payload, verify=False)
            token = response.json()
            if token['session']['valid'] == True:
                logging.info("Token in keyring is valid.")
            else:
                logging.error("Stored token is invalid, fetching a new one...")
                token = pihole_auth(pihole_server, pihole_password)
                if not token:
                    logging.error("Failed to authenticate with Pi-hole server.")
                    return
                # Store the token in the keyring
                put_token_keyring(token)
                logging.info("Token stored in keyring successfully.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Authentication failed: {e}")
            return None

def main():
    """
    Main function to execute the script.
    """

    get_valid_token()

if __name__ == "__main__":
   main()