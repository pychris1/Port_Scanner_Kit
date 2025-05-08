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
import time


# Generate a new log file with a timestamp each time the program starts
LOG_FILE = f"scan_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
DEBUG_MODE = True  # Set to False to disable logging

# Define vulnerability thresholds for scoring
VULNERABILITY_THRESHOLDS = {
    "harmless": 1,
    "mild": 2,
    "moderate": 3,
    "high": 4,
    "very_high": 5,
}

# Common ports that are often vulnerable (Telnet, FTP, RDP, etc.)
COMMON_VULNERABLE_PORTS = [21, 22, 23, 25, 110, 143, 445, 3389]

# Create a session object for faster HTTP requests
session = requests.Session()

def grab_banner(ip, port):
    """Attempts to grab the service banner from an open port."""
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
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return "❌ Could not resolve IP.", None

    results = []
    for i in range(4):
        try:
            start = time.time()
            with socket.create_connection((ip, 80), timeout=2):
                end = time.time()
                latency = round((end - start) * 1000, 2)
                results.append(f"Reply from {ip}: time={latency}ms")
        except Exception as e:
            results.append(f"Request to {ip} failed: {e}")
        time.sleep(1)

    return "\n".join(results), ip





def log_result(entry):
    """Logs results to a file if DEBUG_MODE is enabled."""
    if DEBUG_MODE:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as log:
            log.write(f"\n[{timestamp}] {entry}\n")
        print(f"📝 Results saved to {LOG_FILE}")


# Geo-IP Lookup (Similar to before)
def geo_ip_lookup(ip):
    """Fetches Geo-IP information for a given IP address and prints it to the terminal."""
    try:
        response = session.get(f"https://ipinfo.io/{ip}/json", timeout=2)
        response.raise_for_status()  # Raise an error for HTTP issues
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

        # Print geo info to the terminal
        print("\n🌍 Geo-IP Information:")
        for key, value in geo_info.items():
            print(f"   {key}: {value}")

        log_result(f"Geo-IP Lookup for {ip}: {geo_info}")
        return geo_info
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching Geo-IP data: {e}")
        return None


# Scan Ports (No changes needed here)
for future in concurrent.futures.as_completed(futures):
    result = future.result()
    if result:
        open_ports.append(result)
        state = result["state"]
        port = result["port"]
        banner = result.get("banner", "No banner")

        st.text(f"Port {port}: {state.upper()} - {banner if banner else ''}")

# Assess Vulnerability (Enhance with more logic)
def assess_vulnerability(ip, open_ports=None):
    """Assesses vulnerability based on the number of open ports and their risk level."""
    score = 1  # Default to "harmless"

    if open_ports is None:
        open_ports = scan_ports(ip)  # Avoid re-scanning if ports are already provided

    critical_ports = [port for port in open_ports if port in COMMON_VULNERABLE_PORTS]

    if critical_ports:
        score = VULNERABILITY_THRESHOLDS["very_high"]
    elif len(open_ports) > 50:
        score = VULNERABILITY_THRESHOLDS["high"]
    elif len(open_ports) > 20:
        score = VULNERABILITY_THRESHOLDS["moderate"]
    elif len(open_ports) > 5:
        score = VULNERABILITY_THRESHOLDS["mild"]

    # Print the vulnerability score to terminal
    print(f"🛡️ Vulnerability score for {ip}: {score} / 5")

    # Log the score to the log file
    log_result(f"Vulnerability score for {ip}: {score} / 5")

    return score

def lookup_ip_threat(ip):
    """Looks up the threat reputation of an IP using AbuseIPDB API."""
    API_KEY = 'f1ca7d0cae6b8e9c4e60a813db3682c8a52b3afc9212ec40d107362e46af6fe7c839545cb023038f'  # Replace with your real key

    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=5)
        response.raise_for_status()
        data = response.json()['data']

        abuse_confidence_score = data.get('abuseConfidenceScore', 0)
        total_reports = data.get('totalReports', 0)
        country = data.get('countryCode', 'Unknown')

        lookup_result = (
            f"\n🚨 Threat Intelligence Lookup for {ip}:\n"
            f"   Country: {country}\n"
            f"   Abuse Confidence Score: {abuse_confidence_score}%\n"
            f"   Total Reports: {total_reports}"
        )
        print(lookup_result)
        log_result(lookup_result)

        if abuse_confidence_score >= 50:
            warning = "⚠️ WARNING: This IP is likely malicious!"
            print(warning)
            log_result(warning)
        else:
            clean = "✅ This IP appears relatively clean."
            print(clean)
            log_result(clean)

    except requests.exceptions.RequestException as e:
        error = f"❌ Error during threat lookup: {e}"
        print(error)
        log_result(error)



# Interactive terminal (Expand with system monitoring and other features)
def interactive_terminal():
    """Starts the interactive terminal for user commands."""
    print("\n🚀 Welcome to the Interactive Terminal! Type 'help' for commands.\n")

    while True:
        command = input("> ").strip().lower()

        if command.startswith("ping "):
            host = command.split("ping ")[1]
            ip = ping_host(host)
            if ip:
                print(f"🌍 IP Address of {host}: {ip}")

        elif command.startswith("geo "):
            ip = command.split("geo ")[1]
            geo_info = geo_ip_lookup(ip)
            if geo_info:
                print("\n🌍 Geo-IP Information:")
                for key, value in geo_info.items():
                    print(f"   {key}: {value}")

        elif command.startswith("scan "):
            ip = command.split("scan ")[1]
            open_ports = scan_ports(ip)
            if open_ports:
                print("\n📜 Open Ports and Services:")
                for port, banner in open_ports:
                    print(f"  - Port {port} open")
                    if banner:
                        print(f"    ↳ Service Detected: {banner}")
                    else:
                        print(f"    ↳ No banner detected")

        elif command.startswith("vuln "):
            ip = command.split("vuln ")[1]
            score = assess_vulnerability(ip)
            print(f"🛡️ Vulnerability score for {ip}: {score} / 5")

        elif command.startswith("threat "):
            ip = command.split("threat ")[1]
            lookup_ip_threat(ip)

        elif command == "help":
            print("\nAvailable Commands:")
            print("  ping [HOST]    - Ping a domain/IP (e.g., ping google.com)")
            print("  geo [IP]       - Get Geo-IP info (e.g., geo 8.8.8.8)")
            print("  scan [IP]      - Scan common ports and detect services (e.g., scan scanme.nmap.org)")
            print("  vuln [IP]      - Assess vulnerability score for an IP (e.g., vuln 192.168.1.1)")
            print("  threat [IP]    - Perform a Threat Intelligence lookup (e.g., threat 1.2.3.4)")
            print("  exit           - Exit the terminal\n")

        elif command == "exit":
            print("👋 Exiting...")
            break

        else:
            print("❌ Invalid command. Type 'help' for options.")


# Run the interactive terminal
# All your imports at the top (socket, requests, etc.)
# Your ping_host(), scan_ports(), geo_ip_lookup(), lookup_ip_threat(), etc.

    # your terminal interface code
if __name__ == "__main__":
    interactive_terminal()

