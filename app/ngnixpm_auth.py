# Reference: https://github.com/NginxProxyManager/nginx-proxy-manager/tree/develop/backend/schema

import requests
import keyring
from keyring.errors import PasswordDeleteError
import os
from dotenv import load_dotenv
import json
from datetime import datetime, timezone
from BearerAuth import BearerAuth
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


# Constants
KEYRING_SERVICE = "nginxpm-auth"

def get_bearer_token(api_url, identity, secret):
    """Retrieve a new bearer token from the API."""
    url = f"{api_url}/api/tokens"
    headers = {"Content-Type": "application/json"}
    payload = {"identity": identity, "secret": secret}

    try:
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()

        token = data.get("token")
        token_expiry = data.get("expires")

        if not token:
            raise ValueError("Token not found in response")

        logging.info(f"Retrieved new bearer token: {token}")
        return {"bearer_token": token, "expiry_time": token_expiry}
    except requests.exceptions.RequestException as e:
        print(f"Error getting NPM token: {e}")
        return None


def store_token_keyring(token):
    """Store the token in the system keyring."""
    try:
        keyring.delete_password(KEYRING_SERVICE, "bearer_token")
    except PasswordDeleteError:
        pass  # Ignore if the password doesn't exist yet

    keyring.set_password(KEYRING_SERVICE, "bearer_token", json.dumps(token))
    print("Token stored in keyring successfully.")


def get_token_keyring():
    """Retrieve the token from the system keyring."""
    try:
        token = keyring.get_password(KEYRING_SERVICE, "bearer_token")
        return json.loads(token) if token else None
    except keyring.errors.KeyringError as e:
        logging.error(f"Error retrieving token from keyring: {e}")
        return None


def get_valid_token(api_url, identity, secret):
    """Retrieve a valid token, refreshing it if necessary."""
    token_data = get_token_keyring()
    if not token_data:
        logging.info("No token found in keyring, retrieving a new one...")
        token_data = get_bearer_token(api_url, identity, secret)
        if token_data:
            store_token_keyring(token_data)
        return token_data.get("bearer_token") if token_data else None

    bearer_token = token_data["bearer_token"]
    url = f"{api_url}/api/users/"

    try:
        response = requests.get(url, auth=BearerAuth(bearer_token))
        response.raise_for_status()
        logging.info(f"Stored Bearer Token is Reused")
        return bearer_token
    except requests.exceptions.RequestException:
        logging.error("Token is invalid or expired, retrieving a new one...")
        token_data = get_bearer_token(api_url, identity, secret)
        if token_data:
            store_token_keyring(token_data)
        return token_data.get("bearer_token") if token_data else None


def set_extended_token(api_url, token, expiry_duration):
    """Set an extended token expiry duration."""
    url = f"{api_url}/api/tokens?expiry={expiry_duration}"

    try:
        logging.info("Setting extended token expiry duration to 10 years...")
        response = requests.get(url, auth=BearerAuth(token))
        response.raise_for_status()

        data = response.json()
        token_expiry = data.get("expires")

        if not token_expiry:
            raise ValueError("'Expires' not found in response")

        current_time = datetime.now(timezone.utc)
        token_expiry_time = datetime.fromisoformat(token_expiry.replace("Z", "+00:00"))
        token_expiry_duration = token_expiry_time - current_time
        new_token_expiry = token_expiry_duration.days // 365

        print(f"Bearer token: {token}, Token expiry: {new_token_expiry} years")
        return token, new_token_expiry
    except requests.exceptions.RequestException as e:
        print(f"Error setting extended token: {e}")
        return None
