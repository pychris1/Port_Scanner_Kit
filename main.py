import socket
import datetime
import platform
import subprocess
import requests
import concurrent.futures
import os
import json
import shutil
import streamlit as st
from ping3 import ping

# --- Setup ---
os.makedirs("logs", exist_ok=True)
LOG_FILE = f"logs/scan_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
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

# --- Ping Function (4-packet simulation) ---
def ping_host(host):
    try:
        ip = socket.gethostbyname(host)
        latencies = []

        for _ in range(4):
            latency = ping(ip, timeout=2)
            latencies.append(latency)

        responses = []
        received = 0

        for i, latency in enumerate(latencies, 1):
            if latency is not None:
                received += 1
                responses.append(f"Reply {i}: time={round(latency * 1000, 2)} ms")
            else:
                responses.append(f"Reply {i}: Request timed out.")

        sent = 4
        lost = sent - received
        loss_percent = round((lost / sent) * 100)

        summary = f"""Pinging {host} [{ip}] with {sent} packets:
{chr(10).join(responses)}

Packets: Sent = {sent}, Received = {received}, Lost = {lost} ({loss_percent}% loss)
IP: {ip}
"""
        return summary, ip

    except Exception as e:
        return f"Ping failed: {e}", None
# --- Logging ---
def log_result(entry):
    if DEBUG_MODE:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as log:
            log.write(f"\n[{timestamp}] {entry}\n")
        print(f"📝 Results saved to {LOG_FILE}")

# --- Geo IP ---
def geo_ip_lookup(ip):
    try:
        response = session.get(f"https://ipinfo.io/{ip}/json", timeout=2)
        response.raise_for_status()
        data = response.json()

        geo_info = {
            "IP": data.get("ip", "Unknown"),
            "City": data.get("city", "Unknown"),
            "Region": data.get("region", "Unknown"),
            "Country": data.get("country", "Unknown"),
            "ISP": data.get("org", "Unknown"),
            "Location": data.get("loc", "Unknown"),
            "Timezone": data.get("timezone", "Unknown"),
        }

        print("\n🌍 Geo-IP Information:")
        for key, value in geo_info.items():
            print(f"   {key}: {value}")

        log_result(f"Geo-IP Lookup for {ip}: {geo_info}")
        return geo_info
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching Geo-IP data: {e}")
        return None

# --- Port Scanning ---
def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, port))
            banner = s.recv(1024)
            return banner.decode(errors="ignore").strip()
    except Exception:
        return None

def scan_ports(ip, port_range=(1, 1024)):
    print(f"\n🔍 Scanning {ip} for open ports...\n")
    open_ports = []

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

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(scan_port, range(port_range[0], port_range[1] + 1))

    for result in results:
        if result:
            port, banner = result
            open_ports.append((port, banner))
            print(f"  - Port {port} open")
            log_result(f"Port {port} open")
            if banner:
                print(f"    ↳ Service Detected: {banner}")
                log_result(f"    ↳ Service Detected: {banner}")
            else:
                print("    ↳ No banner detected")
                log_result("    ↳ No banner detected")

    if not open_ports:
        result = f"❌ No open ports found on {ip}"
        print(result)
        log_result(result)

    return open_ports

# --- Vulnerability Scoring ---
def assess_vulnerability(ip, open_ports=None):
    score = 1
    if open_ports is None:
        open_ports = scan_ports(ip)

    critical_ports = [port for port, _ in open_ports if port in COMMON_VULNERABLE_PORTS]

    if critical_ports:
        score = VULNERABILITY_THRESHOLDS["very_high"]
    elif len(open_ports) > 50:
        score = VULNERABILITY_THRESHOLDS["high"]
    elif len(open_ports) > 20:
        score = VULNERABILITY_THRESHOLDS["moderate"]
    elif len(open_ports) > 5:
        score = VULNERABILITY_THRESHOLDS["mild"]

    print(f"🛡️ Vulnerability score for {ip}: {score} / 5")
    log_result(f"Vulnerability score for {ip}: {score} / 5")
    return score

# --- Threat Intelligence ---
def lookup_ip_threat(ip):
    API_KEY = st.secrets["api_keys"]["abuseipdb"]
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

# --- Optional Terminal CLI (for testing outside Streamlit) ---
def interactive_terminal():
    print("\n🚀 Welcome to the Interactive Terminal! Type 'help' for commands.\n")

    while True:
        command = input("> ").strip().lower()

        if command.startswith("ping "):
            host = command.split("ping ")[1]
            result, _ = ping_host(host)
            print(result)

        elif command.startswith("geo "):
            ip = command.split("geo ")[1]
            geo_info = geo_ip_lookup(ip)
            if geo_info:
                for key, value in geo_info.items():
                    print(f"   {key}: {value}")

        elif command.startswith("scan "):
            ip = command.split("scan ")[1]
            scan_ports(ip)

        elif command.startswith("vuln "):
            ip = command.split("vuln ")[1]
            assess_vulnerability(ip)

        elif command.startswith("threat "):
            ip = command.split("threat ")[1]
            lookup_ip_threat(ip)

        elif command == "help":
            print("""
Commands:
  ping [HOST]
  geo [IP]
  scan [IP]
  vuln [IP]
  threat [IP]
  exit
""")
        elif command == "exit":
            break
        else:
            print("❌ Invalid command.")

if __name__ == "__main__":
    interactive_terminal()
