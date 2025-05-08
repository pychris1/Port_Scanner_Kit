# --- gui.py (Streamlit Frontend) ---
import streamlit as st
import socket
import json
import pandas as pd
from main import ping_host, geo_ip_lookup, scan_ports, lookup_ip_threat, assess_vulnerability
import requests

st.set_page_config(page_title="🛡️ Cyber Scanner", layout="centered")
st.title("🛡️ Network Vulnerability & Threat Intelligence Scanner")

host_input = st.text_input("Enter a domain or IP")
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    ping_clicked = st.button("Ping")
with col2:
    geo_clicked = st.button("Geo-IP")
with col3:
    scan_clicked = st.button("Port Scan")
with col4:
    vuln_clicked = st.button("Vulnerability")
with col5:
    threat_clicked = st.button("Threat Check")

if host_input:
    try:
        ip = socket.gethostbyname(host_input)

        if ping_clicked:
            with st.spinner("Pinging target (4 pings ~2s)..."):
                result, resolved_ip = ping_host(host_input)
            st.subheader("📶 Ping Result")
            st.code(result)

        if geo_clicked:
            st.subheader("🌍 Geo-IP Info")
            with st.spinner("Looking up Geo-IP info (1–2 seconds)..."):
                geo_info = geo_ip_lookup(ip)
            if "error" in geo_info:
                st.error(f"❌ Geo-IP Lookup Failed: {geo_info['error']}")
            else:
                st.json(geo_info)
                if "Location" in geo_info:
                    try:
                        lat, lon = map(float, geo_info["Location"].split(","))
                        if (lat, lon) == (0.0, 0.0):
                            st.warning("🌎 No accurate location available for this IP.")
                        else:
                            st.subheader("📍 Approximate Location Map")
                            st.map(pd.DataFrame({"lat": [lat], "lon": [lon]}))
                    except Exception:
                        st.warning("🌎 Could not parse coordinates for mapping.")
                else:
                    st.warning("🌎 Location data not found in Geo-IP results.")

        if scan_clicked:
            st.subheader("🔎 Open Ports")
            with st.spinner("Scanning ports (est. 5–10 seconds)..."):
                results_df = scan_ports(ip)

            open_ports = results_df[results_df['State'] == 'Open']

            if open_ports.empty:
                st.info("✅ All scanned ports are closed or filtered.")
            else:
                for _, row in open_ports.iterrows():
                    st.text(f"Port {row['Port']}: {row['State']} - {row['Banner'] or 'No banner'}")

                st.download_button("📄 Download Results (JSON)",
                                   data=open_ports.to_json(orient="records", indent=2),
                                   file_name="open_ports.json",
                                   mime="application/json")

                st.download_button("📄 Download Results (TXT)",
                                   data=open_ports.to_csv(index=False),
                                   file_name="open_ports.txt",
                                   mime="text/plain")

        if vuln_clicked:
            st.subheader("🛡️ Vulnerability Score")
            with st.spinner("Assessing vulnerability (est. few seconds)..."):
                scan_df = scan_ports(ip)
                score = assess_vulnerability(scan_df)
            st.metric("Risk Level", f"{score} / 5")

                st.subheader("🔎 Passive DNS Records")
        with st.spinner("Querying DNS history..."):
            try:
                dns_response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={host_input}", timeout=5)
                if dns_response.status_code == 200:
                    dns_lines = dns_response.text.strip().split("
")
                    if dns_lines:
                        for line in dns_lines:
                            domain, resolved_ip = line.split(',')
                            st.text(f"{domain} → {resolved_ip}")
                    else:
                        st.info("No passive DNS records found.")
                else:
                    st.error("Failed to fetch passive DNS data.")
            except Exception as e:
                st.error(f"Error querying passive DNS: {e}")

        if threat_clicked:
            st.subheader("🚨 Threat Intelligence")
            with st.spinner("Fetching threat intelligence (est. ~3s)..."):
                threat_info = lookup_ip_threat(ip)
            if "error" in threat_info:
                st.error(f"❌ Threat Lookup Failed: {threat_info['error']}")
            else:
                st.json(threat_info)
                abuse_score = threat_info.get("Abuse Score", 0)
                if abuse_score >= 50:
                    st.error("⚠️ High abuse confidence score — this IP is likely malicious.")
                elif abuse_score >= 20:
                    st.warning("⚠️ Moderate abuse confidence score.")
                else:
                    st.success("✅ Low abuse confidence score. This IP appears safe.")

    except socket.gaierror:
        st.error("❌ Invalid domain or IP address.")
