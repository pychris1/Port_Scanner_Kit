# --- gui.py (Streamlit Frontend) ---
import streamlit as st
import socket
import json
from main import ping_host, geo_ip_lookup, scan_ports, lookup_ip_threat, assess_vulnerability

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
            result, resolved_ip = ping_host(host_input)
            st.subheader("📶 Ping Result")
            st.code(result)

        if geo_clicked:
            st.subheader("🌍 Geo-IP Info")
            geo_info = geo_ip_lookup(host_input)
            st.json(geo_info)

            if 'loc' in geo_info and geo_info['loc']:
                try:
                    lat, lon = map(float, geo_info['loc'].split(','))
                    st.subheader("📍 Approximate Location Map")
                    st.map(data={"lat": [lat], "lon": [lon]})
                except Exception:
                    st.warning("🌎 Could not map the location properly.")

        if scan_clicked:
            st.subheader("🔎 Open Ports")
            results_df = scan_ports(ip)
            for _, row in results_df.iterrows():
                st.text(f"Port {row['Port']}: {row['State']} - {row['Banner'] or 'No banner'}")

            st.download_button("📄 Download Results (JSON)",
                               data=results_df.to_json(orient="records", indent=2),
                               file_name="port_scan_results.json",
                               mime="application/json")

            st.download_button("📄 Download Results (TXT)",
                               data=results_df.to_csv(index=False),
                               file_name="port_scan_results.txt",
                               mime="text/plain")

        if vuln_clicked:
            st.subheader("🛡️ Vulnerability Score")
            scan_df = scan_ports(ip)
            score = assess_vulnerability(scan_df)
            st.metric("Risk Level", f"{score} / 5")

        if threat_clicked:
            st.subheader("🚨 Threat Intelligence")
            threat_info = lookup_ip_threat(ip)
            st.json(threat_info)

    except socket.gaierror:
        st.error("❌ Invalid domain or IP address.")
