from ngnixpm_auth import get_valid_token
import requests
import json
from BearerAuth import BearerAuth

def getProxyHosts(api_url, token):
    """
    Fetch proxy hosts from the Nginx Proxy Manager API.

    Args:
        api_url (str): Base API URL.
        token (str): Bearer token for authentication.

    Returns:
        list: List of proxy hosts.
    """
    url = f"{api_url}/api/nginx/proxy-hosts"
    try:
        response = requests.get(url, auth=BearerAuth(token))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error getting proxy hosts: {e}")
        return None


def getCertificatesList(api_url, token):
    """
    Fetch certificates from the Nginx Proxy Manager API.

    Args:
        api_url (str): Base API URL.
        token (str): Bearer token for authentication.

    Returns:
        list: List of certificates with ID and nice name.
    """
    url = f"{api_url}/api/nginx/certificates"
    try:
        response = requests.get(url, auth=BearerAuth(token))
        response.raise_for_status()
        data = response.json()
        return [
            {"id": cert.get("id"), "nice_name": cert.get("nice_name")}
            for cert in data if "id" in cert and "nice_name" in cert
        ]
    except requests.exceptions.RequestException as e:
        print(f"Error getting certificates: {e}")
        return None


def proxyHostsWithCertificates(proxy_hosts, certificates):
    """
    Add certificate nice_name to each proxy host based on its certificate_id.

    Args:
        proxy_hosts (list): List of proxy host dictionaries.
        certificates (list): List of certificate dictionaries.

    Returns:
        list: Updated proxy_hosts with certificate_name added.
    """
    cert_id_to_nice_name = {cert['id']: cert['nice_name'] for cert in certificates}
    for proxy_host in proxy_hosts:
        cert_id = proxy_host.get('certificate_id', 0)
        if cert_id > 0:
            proxy_host['certificate_name'] = cert_id_to_nice_name.get(cert_id, "Unknown certificate")
        else:
            proxy_host['certificate_name'] = "No certificate"
    return proxy_hosts


def setProxyHost(api_url, token, json_data):
    """
    Set a new proxy host using the Nginx Proxy Manager API.

    Args:
        api_url (str): Base API URL.
        token (str): Bearer token for authentication.
        data (dict): Data for the new proxy host.

    Returns:
        dict: Response from the API.
    """
    url = f"{api_url}/api/nginx/proxy-hosts"
    try:
        response = requests.post(url, json=json_data, auth=BearerAuth(token))
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error setting proxy host: {e}")
        return None