# --- main.py (Logic Layer) ---
import socket
import datetime
import requests
import concurrent.futures
import os
import json
import time
import errno
import pandas as pd

# Setup
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

# Logging
def log_result(entry):
    if DEBUG_MODE:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a") as log:
            log.write(f"\n[{timestamp}] {entry}\n")
        print(f"📝 Results saved to {LOG_FILE}")

# Banner Grabber
def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, port))
            banner = s.recv(1024)
            return banner.decode(errors="ignore").strip()
    except Exception:
        return None

# Port Scanner with State Classification
def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            result = sock.connect_ex((ip, port))

            if result == 0:
                banner = grab_banner(ip, port)
                return {"Port": port, "State": "Open", "Banner": banner}
            elif result == errno.ECONNREFUSED:
                return {"Port": port, "State": "Closed", "Banner": None}
            else:
                return {"Port": port, "State": "Filtered", "Banner": None}
    except socket.timeout:
        return {"Port": port, "State": "Filtered", "Banner": None}
    except Exception as e:
        return {"Port": port, "State": f"Error ({e})", "Banner": None}

def scan_ports(ip, port_range=(1, 1024)):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in range(port_range[0], port_range[1] + 1)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return pd.DataFrame(open_ports)

# Ping Function

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

# Geo IP

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
        log_result(f"Geo-IP Lookup for {ip}: {geo_info}")
        return geo_info
    except requests.exceptions.RequestException as e:
        log_result(f"Geo-IP lookup failed: {e}")
        return {"error": str(e)}

# Threat Intelligence

def lookup_ip_threat(ip):
    API_KEY = 'YOUR_REAL_API_KEY'
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': API_KEY}

    try:
        response = session.get(url, headers=headers, params=querystring, timeout=5)
        response.raise_for_status()
        data = response.json()['data']
        return {
            "Country": data.get("countryCode", "Unknown"),
            "Abuse Score": data.get("abuseConfidenceScore", 0),
            "Total Reports": data.get("totalReports", 0)
        }
    except Exception as e:
        return {"error": str(e)}

# Vulnerability Assessment
def assess_vulnerability(open_ports_df):
    score = 1
    ports = open_ports_df["Port"].tolist()
    critical_ports = [port for port in ports if port in COMMON_VULNERABLE_PORTS]

    if critical_ports:
        score = VULNERABILITY_THRESHOLDS["very_high"]
    elif len(ports) > 50:
        score = VULNERABILITY_THRESHOLDS["high"]
    elif len(ports) > 20:
        score = VULNERABILITY_THRESHOLDS["moderate"]
    elif len(ports) > 5:
        score = VULNERABILITY_THRESHOLDS["mild"]

    log_result(f"Vulnerability score: {score} / 5")
    return score
