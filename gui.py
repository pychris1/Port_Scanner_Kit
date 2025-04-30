import streamlit as st
import socket
import datetime
import platform
import subprocess
import requests
import concurrent.futures
import os
import json

# --- Setup ---
LOG_FILE = f"scan_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
DEBUG_MODE = True
VULNERABILITY_THRESHOLDS = {
    "harmless": 1,
    "mild": 2,
    "moderate": 3,
    "high": 4,
    "very_high": 5,
}
COMMON_VULNERABLE_PORTS = [21, 22, 23, 25, 110, 143, 445, 3389]
session = requests.Session()

# --- Core Functions ---
def log_result(entry):
    if DEBUG_MODE:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as log:
            log.write(f"\n[{timestamp}] {entry}\n")


def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, port))
            banner = s.recv(1024)
            return banner.decode(errors="ignore").strip()
    except Exception:
        return None


def ping_host(host):
    try:
        ip_address = socket.gethostbyname(host)
    except socket.gaierror:
        return "❌ Could not resolve IP for host.", None

    ping_executable = shutil.which("ping")
    if not ping_executable:
        return "❌ Ping utility not found on system.", None

    cmd = [ping_executable, "-n", "4", host] if platform.system().lower() == "windows" else [ping_executable, "-c", "4", host]

    with st.spinner("📡 Pinging... please wait..."):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            output = result.stdout.strip()
            log_result(f"Ping to {host}:\n{output}")
            return output, ip_address
        except subprocess.TimeoutExpired:
            log_result(f"Ping to {host} timed out.")
            return "⏱️ Ping timed out.", ip_address
        except Exception as e:
            log_result(f"Ping to {host} failed: {e}")
            return f"❌ Ping failed: {e}", ip_address


def geo_ip_lookup(ip):
    try:
        resolved_ip = socket.gethostbyname(ip)
        response = session.get(f"https://ipinfo.io/{resolved_ip}/json", timeout=2)
        response.raise_for_status()
        data = response.json()
        log_result(f"Geo-IP Lookup for {resolved_ip}: {data}")
        return data
    except Exception as e:
        log_result(f"Geo-IP lookup failed: {e}")
        return {"error": str(e)}


def scan_ports(ip, port_range=(1, 1024)):
    open_ports = []
    total_ports = port_range[1] - port_range[0] + 1
    progress_bar = st.progress(0)
    status_text = st.empty()

    def scan_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)
                if sock.connect_ex((ip, port)) == 0:
                    banner = grab_banner(ip, port)
                    return (port, banner)
        except Exception:
            pass
        return None

    scanned = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, port): port for port in range(port_range[0], port_range[1] + 1)}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
            scanned += 1
            progress_bar.progress(min(scanned / total_ports, 1.0))
            status_text.text(f"Scanning ports... {scanned}/{total_ports}")

    status_text.text("Scan complete!")
    return open_ports


def assess_vulnerability(open_ports):
    score = 1
    ports_only = [p for p, _ in open_ports]
    critical_ports = [port for port in ports_only if port in COMMON_VULNERABLE_PORTS]

    if critical_ports:
        score = VULNERABILITY_THRESHOLDS["very_high"]
    elif len(open_ports) > 50:
        score = VULNERABILITY_THRESHOLDS["high"]
    elif len(open_ports) > 20:
        score = VULNERABILITY_THRESHOLDS["moderate"]
    elif len(open_ports) > 5:
        score = VULNERABILITY_THRESHOLDS["mild"]

    return score


def lookup_ip_threat(ip):
    API_KEY = 'f1ca7d0cae6b8e9c4e60a813db3682c8a52b3afc9212ec40d107362e46af6fe7c839545cb023038f'
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': API_KEY}

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        response.raise_for_status()
        data = response.json()['data']
        log_result(f"Threat Lookup for {ip}: {data}")
        return data
    except Exception as e:
        log_result(f"Threat lookup failed: {e}")
        return {"error": str(e)}

# --- Streamlit App ---
st.set_page_config(page_title="Cyber Scanner", layout="centered", initial_sidebar_state="collapsed")
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
            ports = scan_ports(ip)
            if ports:
                results = [{"Port": port, "Banner": banner or "No banner"} for port, banner in ports]
                for r in results:
                    st.text(f"Port {r['Port']} open - {r['Banner']}")

                text_export = "\n".join([f"Port {r['Port']} open - {r['Banner']}" for r in results])
                st.download_button("📄 Download Scan Results (TXT)", data=text_export, file_name="port_scan_results.txt", mime="text/plain")

                json_export = json.dumps(results, indent=2)
                st.download_button("📄 Download Scan Results (JSON)", data=json_export, file_name="port_scan_results.json", mime="application/json")
            else:
                st.warning("No open ports found.")

        if vuln_clicked:
            ports = scan_ports(ip)
            score = assess_vulnerability(ports)
            st.subheader("🛡️ Vulnerability Score")
            st.metric("Risk Level", f"{score} / 5")

        if threat_clicked:
            st.subheader("🚨 Threat Intelligence")
            threat_info = lookup_ip_threat(ip)
            st.json(threat_info)

    except socket.gaierror:
        st.error("❌ Invalid domain or IP address.")
