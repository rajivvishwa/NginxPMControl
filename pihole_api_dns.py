import requests
import logging
from dotenv import load_dotenv
import pandas as pd
import os
import keyring
from keyring.errors import PasswordDeleteError
from pihole_auth import get_valid_token
from pihole_auth import get_token_keyring
import streamlit as st

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
KEYRING_SERVICE = "pihole-auth"
pihole_server = None
sid = None
csrf = None

def get_cnames(pihole_server):
    """
    Fetches CNAME records from the Pi-hole server.
    """
    get_valid_token()
    sid, csrf = get_token_keyring()

    if not sid or not csrf:
        logging.error("Failed to retrieve session ID or CSRF token from keyring.")
        return

    url = f'https://{pihole_server}/api/config/dns/cnameRecords'

    payload = {}
    headers = {
    "X-FTL-SID": sid,
    "X-FTL-CSRF": csrf
    }

    response = requests.request("GET", url, headers=headers, data=payload, verify=False)

    records = response.json()["config"]["dns"]["cnameRecords"]

    # Split each record into host and target
    split_records = [rec.split(',') for rec in records]

    # Create DataFrame
    cnames_df = pd.DataFrame(split_records, columns=["host", "target"])

    return cnames_df  

def put_cnames(pihole_server, host, target):
    """
    Updates CNAME records on the Pi-hole server.
    """
    get_valid_token()
    sid, csrf = get_token_keyring()

    if not sid or not csrf:
        logging.error("Failed to retrieve session ID or CSRF token from keyring.")
        return
    
    #test.astra.home%2Castra.infv
    logging.info(f"Host: {host}")
    logging.info(f"Target: {target}")

    url = f'https://{pihole_server}/api/config/dns/cnameRecords/{host}%2C{target}'
    logging.info(f"Sending PUT request to {url}")

    payload = {}

    headers = {
    "X-FTL-SID": sid,
    "X-FTL-CSRF": csrf
    }

    response = requests.put(url, headers=headers, data=payload, verify=False)

    logging.info(f"Response: {response.json()} and Response code: {response.status_code}")

    # if response.json()["config"] is empty, then cname record is not. if config is not returned, then cname was updated

    if "config" not in response.json() and "error" not in response.json():
        logging.info("CNAME record updated successfully.")
    else:
        logging.error(f"Failed to update CNAME record: {response.json()}")
    
    return response

def main():
    """
    Main function to execute the script.
    """

    global pihole_server
    global sid
    global csrf

    # Load environment variables from .env file
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
    pihole_server = os.getenv("PIHOLE_SERVER")
    pihole_password = os.getenv("PIHOLE_PASSWORD")

    # Retrieve the token from the keyring
    get_valid_token()
    sid, csrf = get_token_keyring()

    if not sid or not csrf:
        logging.error("Failed to retrieve session ID or CSRF token from keyring.")
        return

    # Print the session ID and CSRF token
    logging.info(f"Session ID: {sid}")
    logging.info(f"CSRF Token: {csrf}")
    # Fetch CNAME records
    cnames_df = get_cnames(pihole_server)

    logging.info("CNAME Records:")
    logging.info(cnames_df)

    # Display the DataFrame in Streamlit
    st.title("Pi-hole CNAME Records")
    st.write("CNAME records fetched from the Pi-hole server:")

    st.dataframe(cnames_df)

    put_cnames(pihole_server, "test4.astra.home", "astra.infv")

if __name__ == "__main__":
   main()