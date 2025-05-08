import os
import streamlit as st
import pandas as pd
import json
from dotenv import load_dotenv
from ngnixpm_auth import get_valid_token
from glances_api import get_container_data
from pihole_api_dns import get_cnames
from pihole_api_dns import put_cnames
import ngnixpm_proxyhosts as npm_ph


def find_free_port(port_range, sorted_df, range_size=100):
    """
    Find a free port starting with port_range itself. If port_range is used,
    find the first available port within +/- range_size of port_range.

    Args:
        port_range (int): The preferred port number.
        sorted_df (DataFrame or list): DataFrame or list containing used ports.
        range_size (int): Size of the port range to search within (default: 100).

    Returns:
        int: Free port number or None if all ports in the range are used.
    """
    used_ports = set(sorted_df['forward_port'].values if hasattr(sorted_df, 'values') else sorted_df)
    if port_range not in used_ports:
        return port_range

    start_port = max(0, port_range - range_size)
    end_port = min(65535, port_range + range_size)

    for offset in range(1, range_size + 1):
        lower_port = port_range - offset
        if lower_port >= start_port and lower_port not in used_ports:
            return lower_port
        higher_port = port_range + offset
        if higher_port <= end_port and higher_port not in used_ports:
            return higher_port
    return None


def displayProxyHosts(proxy_hosts, DEFAULT_DOMAIN):
    """
    Display proxy hosts in a Streamlit app.

    Args:
        proxy_hosts (list): List of proxy hosts.

    Returns:
        DataFrame: Filtered DataFrame of proxy hosts.
    """

    st.write("Here are the proxy hosts retrieved from the API:")

    if not isinstance(proxy_hosts, list):
        try:
            proxy_hosts = json.loads(proxy_hosts)
        except TypeError:
            st.error("Invalid data format. Expected JSON string or list.")
            return pd.DataFrame()

    processed_data = []
    for item in proxy_hosts:
        domain_names_str = ", ".join(item["domain_names"])
        item["public_url"] = f"http://{domain_names_str}"
        item["local_url"] = f"{item['forward_scheme']}://{item['forward_host']}:{item['forward_port']}"
        processed_data.append({
            "certificate_name": item["certificate_name"],
            "public_url": item["public_url"],
            "local_url": item["local_url"],
            "ssl_forced": item["ssl_forced"],
            "forward_port": item["forward_port"],
            "http2_support": item["http2_support"],
            "domain_names": domain_names_str,
            "caching_enabled": item["caching_enabled"],
            "hsts_enabled": item["hsts_enabled"],
            "hsts_subdomains": item["hsts_subdomains"]
        })

    df = pd.DataFrame(processed_data)
    cert_selection = sorted(df['certificate_name'].dropna().unique().tolist())
    selected_cert = st.radio("Select Server:", cert_selection, cert_selection.index(DEFAULT_DOMAIN), horizontal=True)

    filtered_apps = sorted(
        df[df['certificate_name'] == selected_cert]['domain_names'].dropna().unique().tolist()
    ) if selected_cert else sorted(df['domain_names'].dropna().unique().tolist())

    selected_apps = st.multiselect("Select Apps:", filtered_apps)

    selection_df = pd.DataFrame(
        {
            "Server Selection": selected_cert,
            "App Selection": selected_apps,
            "Forward Port": [int(df['forward_port'][i]) for i in df[df['domain_names'].isin(selected_apps)].index.to_list()]
        }
    )
    st.table(selection_df)

    #st.write(f"Server Selection: {selected_cert}")
    #st.write(f"App Selection: {selected_apps}")

    #selected_app_index = df[df['domain_names'].isin(selected_apps)].index.to_list()
    #st.write(f"Forward Port: {df['forward_port'][selected_app_index]}")
    #st.write(f"Forward Port: {[int(df['forward_port'][i]) for i in selected_app_index]}")

    filtered_df = df[df['certificate_name'] == selected_cert] if selected_cert else df
    if selected_apps:
        filtered_df = filtered_df[filtered_df['domain_names'].isin(selected_apps)]

    st.dataframe(
        filtered_df,
        column_config={
            "public_url": st.column_config.LinkColumn("Public Url"),
            "local_url": st.column_config.LinkColumn("Local Url"),
        },
        height=35*len(filtered_df)+38
    )
    return filtered_df


def displayFreePort(filtered_df):
    """
    Display free port finder in a Streamlit app.

    Args:
        filtered_df (DataFrame): Filtered DataFrame of proxy hosts.
    """
    sorted_df = filtered_df.sort_values(by="forward_port")

    slider_port_choice = st.slider(
        "Select port number", 
        min_value=1024,
        max_value=49000,
        step=1)

    # Text input
    text_port_choice = st.text_input("Or enter port number", value=str(slider_port_choice))

    # Ensure the text input is a valid integer within port range
    try:
        text_port = int(text_port_choice)
        if 0 <= text_port <= 49000:
            port_choice = text_port
        else:
            st.warning("Port number must be between 1024 and 65535.")
            port_choice = slider_port_choice
    except ValueError:
        st.warning("Please enter a valid integer.")
        port_choice = slider_port_choice

    st.write("Selected Port :", port_choice)

    used_ports = set(sorted_df['forward_port'].values if hasattr(sorted_df, 'values') else sorted_df)
    if port_choice not in used_ports:
        st.success(f"Selected port {port_choice} is available.")
    else:
        free_port = find_free_port(port_choice, sorted_df)
        if free_port:
            st.warning(f"Selected port {port_choice} is already in use. Found free port: {free_port}")
        else:
            st.error(f"Selected port {port_choice} is already in use, and no free ports are available within ±100 range.")

    st.write("Here are the list of ports in use:")
    st.table([
        f"{port} ({domain})"
        for port, domain in zip(sorted_df["forward_port"], sorted_df["domain_names"])
    ])

def displaySetProxyHosts(api_url, bearer_token, DEFAULT_DOMAIN, DEFAULT_HOST, certificates):
    """
    Display set proxy hosts in a Streamlit app.

    Args:
        None
    """
    st.write("Set Proxy Host")
    col1, col2, col3 = st.columns(3)
    with col1:
        domain_names = st.text_input("Domain Name", value=DEFAULT_DOMAIN)
        forward_scheme = st.selectbox("Forward Scheme", ["http", "https"])
        forward_port = st.number_input("Forward Port", min_value=0, max_value=65535)
        forward_host = st.text_input("Forward Host", value=DEFAULT_HOST)


    with col2:
        st.write("SSL Settings")
        certificate_name = {cert['nice_name']: cert['id'] for cert in certificates}
        # Create a radio button using the nice_name as labels
        
        # find the index of the default domain in the certificate_name keys
        default_domain_index = list(certificate_name.keys()).index(DEFAULT_DOMAIN)

        selected_cert = st.radio("Select a certificate:", list(certificate_name.keys()), index=default_domain_index, horizontal=False)
        # Get the corresponding id
        certificate_id = certificate_name[selected_cert]
        st.divider()
        ssl_forced = st.checkbox("SSL Forced", value=True)
        allow_websocket_upgrade = st.checkbox("Web Sockets Support", value=True)
        block_exploits = st.checkbox("Block Exploits", value=True)
        http2_support = st.checkbox("HTTP/2 Support")
        caching_enabled = st.checkbox("Caching Enabled", value=True)
        # Create a mapping from nice_name to id
        
    json_data = {
        "domain_names": [domain_names],
        "forward_scheme": forward_scheme,
        "forward_port": forward_port,
        "forward_host": forward_host,
        "ssl_forced": ssl_forced,
        "block_exploits": block_exploits,
        "http2_support": http2_support,
        "caching_enabled": caching_enabled,
        "allow_websocket_upgrade": allow_websocket_upgrade,
        "hsts_enabled": False,
        "hsts_subdomains": False,
        "access_list_id": 0,
        "certificate_id": certificate_id
    }
    with col3:
        st.write("This is the JSON data that will be sent to the API.")
        st.json(json_data)
        #with st.popover("See JSON data"):
            

    if st.button("Set Proxy Host"):
        response_json=npm_ph.setProxyHost(api_url, bearer_token, json_data)
        with st.popover("See Response"):
            st.json(response_json)
        if response_json:
            st.success("Proxy host set successfully.")
        else:
            st.error("Failed to set proxy host.")
        pass

def displayGlancesContainerData(glances_servers):
    """
    Display Glances container data in a Streamlit app.

    Args:
        glances_servers (str): Comma-separated list of Glances server IPs.
    """

    container_data = get_container_data(glances_servers)
    container_df = pd.DataFrame(container_data)
    container_df = container_df.sort_values(by='Container Name', key=lambda col: col.str.lower())

    server_selection = sorted(container_df['Server'].dropna().unique().tolist())
    selected_server = st.radio("Select Server:", server_selection, horizontal=True)

    filtered_container_df = container_df[container_df['Server'] == selected_server] if selected_server else container_df

    if not filtered_container_df.empty:
        st.dataframe(filtered_container_df, height=35*len(filtered_container_df)+38)
    else:
        st.error("No container data available for the selected server.")

def displayPiHoleCnames(pihole_server, DEFAULT_HOST):
    """
    Display Pi-hole CNAME records in a Streamlit app.
    """
    # add a button to refresh the data
    if st.button("Refresh CNAME Records"):
        st.experimental_rerun()

    cnames_df = get_cnames(pihole_server)

    target_selection = sorted(cnames_df['target'].dropna().unique().tolist())

    # find the index of the default domain in the target_selection list, if not found, set to 0
    try:
        default_domain_index = target_selection.index(DEFAULT_HOST)
    except ValueError:
        # If the default domain is not found, set to 0
        default_domain_index = 0
    default_domain_index = target_selection.index(DEFAULT_HOST)

    selected_target = st.radio("Choose Target Server:", target_selection, index=default_domain_index, horizontal=True)

    # Filter the DataFrame based on the selected target
    filtered_hosts = sorted(
        cnames_df[cnames_df['target'] == selected_target]['host'].dropna().unique().tolist()
    ) if selected_target else sorted(cnames_df['host'].dropna().unique().tolist())

    # Add a text input for partial search
    search_query = st.text_input("Filter Hosts", value="")
    if search_query:
        filtered_hosts = [host for host in filtered_hosts if search_query.lower() in host.lower()]

    selected_hosts = st.multiselect("Select Hosts:", filtered_hosts)

    selection_df = pd.DataFrame(
        {
            "Target Selection": selected_target,
            "Host Selection": selected_hosts
        }
    )

    filtered_df = cnames_df[cnames_df['target'] == selected_target] if selected_target else cnames_df
    if selected_hosts:
        filtered_df = filtered_df[filtered_df['host'].isin(selected_hosts)]

    st.dataframe(
        filtered_df,
        height=35*len(filtered_df)+38
    )
    return filtered_df

def displayAddPiholeCname(pihole_server, DEFAULT_HOST):
    """
    Add a CNAME record to the Pi-hole server.
    """
    response = {}

    st.write("Add CNAME Record")
    
    
    cnames_df = get_cnames(pihole_server)

    target_selection = sorted(cnames_df['target'].dropna().unique().tolist())


    try:
        default_domain_index = target_selection.index(DEFAULT_HOST)
    except ValueError:
        # If the default domain is not found, set to 0
        default_domain_index = 0
    default_domain_index = target_selection.index(DEFAULT_HOST)

    target = st.selectbox("Select Target", options=target_selection, index=default_domain_index)

    placeholder_host = "***." + target.split(".")[0] + ".home"
    host = st.text_input("Host", value=placeholder_host)

    if host in cnames_df['host'].values:
        st.error(f"Host {host} already exists. Please choose a different host.")
        return

    # Add a button to trigger the CNAME record addition
    if st.button("Add CNAME Record", type="primary"):
        if target and host:
            st.info(f"Adding CNAME record: {host} -> {target}")
            response = put_cnames(pihole_server, host, target)
        else:
            st.error("Please provide both host and target values.")
        
        if "config" not in response.json() and "error" not in response.json():
            st.success(f"CNAME record updated successfully. Reponse : {response.json()}")
        else:
            st.error(f"Failed to update CNAME record: {response.json()}")


    
def main():
    """
    Main function to run the Streamlit app.
    """
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))
    api_url = os.getenv("NPM_API_URL")
    identity = os.getenv("NPM_IDENTITY")
    secret = os.getenv("NPM_SECRET")
    default_domain = os.getenv("DEFAULT_DOMAIN")
    default_host = os.getenv("DEFAULT_HOST")
    glances_servers = os.getenv("GLANCES_SERVERS")
    pihole_server = os.getenv("PIHOLE_SERVER")
    pihole_password = os.getenv("PIHOLE_PASSWORD")

    if not api_url or not identity or not secret or not default_domain:
        raise ValueError("NPM_API_URL, NPM_IDENTITY, or NPM_SECRET, DEFAULT_DOMAIN environment variables are not set")

    bearer_token = get_valid_token(api_url, identity, secret)
    if not bearer_token:
        print("Failed to retrieve a valid token.")
        return

    st.set_page_config(layout="wide")

    st.title("NGINX Proxy Manager Control")

    proxy_hosts = npm_ph.getProxyHosts(api_url, bearer_token)
    certificates = npm_ph.getCertificatesList(api_url, bearer_token)


    if proxy_hosts and certificates:
        proxy_hosts = npm_ph.proxyHostsWithCertificates(proxy_hosts, certificates)
    else:
        st.error("Failed to retrieve proxy hosts or certificates.")

    tab1, tab2, tab3, tab4, tab5, tab6= \
        st.tabs(["Proxy Hosts", "Free Port", "Set Proxy Host", \
                 "Glances Container Data", "Pi-hole CNAME Records", "Add CNAME Record"])
    
    with tab1:
        st.markdown("### NGINX Proxy Hosts")
        filtered_df = displayProxyHosts(proxy_hosts, default_domain)
    with tab2:
        st.markdown("### Free Port Finder")
        displayFreePort(filtered_df)
    with tab3:
        st.markdown("### Set Proxy Host")
        displaySetProxyHosts(api_url, bearer_token, default_domain, default_host, certificates)# Add your logic for setting a new proxy host here
    with tab4:
        st.markdown("### Glances Container Data")
        displayGlancesContainerData(glances_servers)
    with tab5:
        st.markdown("### Pi-hole CNAME Records")
        displayPiHoleCnames(pihole_server, default_host)
    with tab6:
        st.markdown("### Add CNAME Record")
        displayAddPiholeCname(pihole_server, default_host)


if __name__ == "__main__":
    main()
