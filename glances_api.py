import requests
import os
import logging
from dotenv import load_dotenv
import pandas as pd


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_container_data(glances_servers):
    """
    Fetches container data from Glances API servers specified in the .env file.

    Returns:
        list: A list of dictionaries containing container information.
    """
    glances_port = "61208"  # Default to 61208 if not set

    container_data = []

    for server in glances_servers.split(","):
        server_ip = server.strip()
        url = f'http://{server_ip}:{glances_port}/api/4/containers'
        logging.info(f"Fetching container data from: {url}")

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx and 5xx)
            data = response.json()

            # Extract relevant fields
            container_data.extend([
                {
                    'Server': server_ip,
                    'Container Name': item.get('name'),
                    'Port': item.get('port'),
                    'Container ID': item.get('id'),
                    'Status': item.get('status'),
                    'Image': item.get('image')[0] if item.get('image') else None
                }
                for item in data
            ])
        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to retrieve data from {url}: {e}")
        except (ValueError, KeyError) as e:
            logging.error(f"Error processing data from {url}: {e}")

    return container_data

def main():
    """
    Main function to execute the script.
    """
    # Load environment variables from .env file
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
    glances_servers = os.getenv("GLANCES_SERVERS")

    container_data = get_container_data(glances_servers)
    container_df = pd.DataFrame(container_data)
    print(container_df)

#if __name__ == "__main__":
#    main()