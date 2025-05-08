# --- gui.py (Streamlit Frontend) ---
import streamlit as st
import socket
import json
import pandas as pd
from main import ping_host, geo_ip_lookup, scan_ports, lookup_ip_threat, assess_vulnerability
import requests

st.set_page_config(page_title="🛡️ Cyber Scanner", layout="centered")
st.markdown("<h1 style='text-align:center;'>🛡️ Network Vulnerability & Threat Intelligence Scanner</h1>", unsafe_allow_html=True)

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
            st.markdown("<p style='text-align:center;'><p style='text-align:center;'>📶 Pinging target (4 pings ~2s)...</p></p>", unsafe_allow_html=True)
            with st.spinner(""):
                result, resolved_ip = ping_host(host_input)
            st.markdown("<h3 style='text-align:center;'>📶 Ping Result</h3>", unsafe_allow_html=True)
            st.code(result)

        if geo_clicked:
            st.markdown("<h3 style='text-align:center;'>🌍 Geo-IP Info</h3>", unsafe_allow_html=True)
            st.markdown("", unsafe_allow_html=True)
            with st.spinner(""):
                geo_info = geo_ip_lookup(ip)

            if "error" in geo_info:
                st.error(f"❌ Geo-IP Lookup Failed: {geo_info['error']}")
            else:
                geo_json = json.dumps(geo_info, indent=2)
                st.markdown("<div style='display: flex; justify-content: center;'>", unsafe_allow_html=True)
                st.code(geo_json)
                st.markdown("</div>", unsafe_allow_html=True)

                if "Location" in geo_info:
                    try:
                        lat, lon = map(float, geo_info["Location"].split(","))
                        if (lat, lon) == (0.0, 0.0):
                            st.warning("🌎 No accurate location available for this IP.")
                        else:
                            st.markdown("<h4 style='text-align:center;'>📍 Approximate Location Map</h4>", unsafe_allow_html=True)
                            st.map(pd.DataFrame({"lat": [lat], "lon": [lon]}))
                    except Exception:
                        st.warning("🌎 Could not parse coordinates for mapping.")
                else:
                    st.warning("🌎 Location data not found in Geo-IP results.")

        if scan_clicked:
            st.markdown("<h3 style='text-align:center;'>🔎 Open Ports</h3>", unsafe_allow_html=True)
            st.markdown("<p style='text-align:center; display: flex; align-items: center; justify-content: center;'>⏳ Scanning ports (est. 5–10 seconds)... <span class='stSpinner'></span></p>", unsafe_allow_html=True)
            with st.spinner(""):
                results_df = scan_ports(ip)

            open_ports = results_df[results_df['State'] == 'Open']

            if open_ports.empty:
                st.info("✅ All scanned ports are closed or filtered.")
            else:
                for _, row in open_ports.iterrows():
                    st.markdown(f"<div style='text-align:center;'>Port {row['Port']}: {row['State']} - {row['Banner'] or 'No banner'}</div>", unsafe_allow_html=True)

                st.markdown("<div style='display: flex; justify-content: center; gap: 10px;'>", unsafe_allow_html=True)
                st.download_button("📄 Download Results (JSON)",
                                   data=open_ports.to_json(orient="records", indent=2),
                                   file_name="open_ports.json",
                                   mime="application/json")
                st.download_button("📄 Download Results (TXT)",
                                   data=open_ports.to_csv(index=False),
                                   file_name="open_ports.txt",
                                   mime="text/plain")
                st.markdown("</div>", unsafe_allow_html=True)

        if vuln_clicked:
            st.markdown("<h3 style='text-align:center;'>🛡️ Vulnerability Score</h3>", unsafe_allow_html=True)
            st.markdown("<p style='text-align:center; display: flex; align-items: center; justify-content: center;'>🔍 Assessing vulnerability (est. few seconds)... <span class='stSpinner'></span></p>", unsafe_allow_html=True)
            with st.spinner(""):
                scan_df = scan_ports(ip)
                score = assess_vulnerability(scan_df)

            st.markdown("<div style='text-align:center;'>", unsafe_allow_html=True)
            st.markdown(f"<div style='text-align:center; font-size: 1.5em;'><strong>Risk Level:</strong> {score} / 5</div>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

            st.markdown("<h3 style='text-align:center;'>🔎 Passive DNS Records</h3>", unsafe_allow_html=True)
            st.markdown("<p style='text-align:center; display: flex; align-items: center; justify-content: center;'>📡 Querying DNS history... <span class='stSpinner'></span></p>", unsafe_allow_html=True)
            with st.spinner(""):
                try:
                    dns_response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={host_input}", timeout=5)
                    if dns_response.status_code == 200:
                        dns_lines = dns_response.text.strip().split("\n")
                        if dns_lines:
                            for line in dns_lines:
                                domain, resolved_ip = line.split(',')
                                st.markdown(f"<div style='text-align:center;'>{domain} → {resolved_ip}</div>", unsafe_allow_html=True)
                        else:
                            st.info("No passive DNS records found.")
                    else:
                        st.error("Failed to fetch passive DNS data.")
                except Exception as e:
                    st.error(f"Error querying passive DNS: {e}")

        if threat_clicked:
            st.markdown("<h3 style='text-align:center;'>🚨 Threat Intelligence</h3>", unsafe_allow_html=True)
            st.markdown("<p style='text-align:center; display: flex; align-items: center; justify-content: center;'>🧠 Fetching threat intelligence (est. ~3s)... <span class='stSpinner'></span></p>", unsafe_allow_html=True)
            with st.spinner(""):
                threat_info = lookup_ip_threat(ip)

            if "error" in threat_info:
                st.error(f"❌ Threat Lookup Failed: {threat_info['error']}")
            else:
                abuse_score = threat_info.get("Abuse Score", 0)
                color = '#d32f2f' if abuse_score >= 50 else ('#f57c00' if abuse_score >= 20 else '#388e3c')
                threat_json = json.dumps(threat_info, indent=2)
                st.markdown(f"""
<div style='display: flex; justify-content: center;'>
  <pre style='background-color: #f0f4c3; color: {color}; padding: 1.5em; border-left: 6px solid {color}; border-radius: 12px; font-family: Menlo, Consolas, monospace; white-space: pre-wrap; text-align: left; box-shadow: 0 6px 16px rgba(0,0,0,0.15); max-width: 85%; font-size: 1rem; line-height: 1.6; overflow-x: auto;'>
{threat_json}
  </pre>
</div>
""", unsafe_allow_html=True)
                abuse_score = threat_info.get("Abuse Score", 0)
                if abuse_score >= 50:
                    st.markdown("<div style='text-align:center; color: red; font-size: 1.1rem; font-weight: 600; background-color: #fdecea; padding: 10px; border-radius: 8px;'>⚠️ High abuse confidence score — this IP is likely malicious.</div>", unsafe_allow_html=True)
                elif abuse_score >= 20:
                    st.markdown("<div style='text-align:center; color: orange; font-size: 1.1rem; font-weight: 600; background-color: #fff8e1; padding: 10px; border-radius: 8px;'>⚠️ Moderate abuse confidence score.</div>", unsafe_allow_html=True)
                else:
                    st.markdown("<div style='text-align:center; color: green; font-size: 1.1rem; font-weight: 600; background-color: #e8f5e9; padding: 10px; border-radius: 8px;'>✅ Low abuse confidence score. This IP appears safe.</div>", unsafe_allow_html=True)

    except socket.gaierror:
        st.error("❌ Invalid domain or IP address.")
