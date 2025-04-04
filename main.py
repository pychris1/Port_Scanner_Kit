import socket
import datetime
import platform
import subprocess
import requests
import concurrent.futures
import os
import json

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


def ping_host(host):
    """Pings a host and returns its response along with IP address and packet info."""
    print(f"\n🔍 Pinging {host}...\n")

    # Resolve the IP address of the host
    try:
        ip_address = socket.gethostbyname(host)
        print(f"🌍 IP Address of {host}: {ip_address}")
    except socket.gaierror:
        print(f"❌ Could not resolve IP for {host}.")
        return None

    # Use 4 packets for both Windows and Linux/macOS
    cmd = ["ping", "-n", "4", host] if platform.system().lower() == "windows" else ["ping", "-c", "4", host]

    try:
        # Run the ping command with a timeout of 5 seconds
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        output = result.stdout.strip()

        if result.returncode == 0:
            print(f"✅ {host} is reachable!")
        else:
            print(f"❌ {host} is not reachable.")

        print(f"\nPacket Information:\n{output}")
        log_result(f"Ping to {host}:\n{output}")
        return ip_address  # Return the IP address of the host
    except subprocess.TimeoutExpired:
        print(f"❌ Ping to {host} timed out. No response after 4 packets.")
        log_result(f"Ping to {host} timed out.")
        return None
    except Exception as e:
        print(f"❌ Ping failed: {e}")
        log_result(f"Ping to {host} failed with error: {e}")
        return None


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
def scan_ports(ip, port_range=(1, 1024)):
    """Scans open ports on a given IP address using multi-threading for speed."""
    print(f"\n🔍 Scanning {ip} for open ports...\n")
    open_ports = []

    def scan_port(port):
        """Attempts to connect to a port to check if it's open."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3)  # Reduced timeout for quicker scans
                if sock.connect_ex((ip, port)) == 0:
                    return port
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(scan_port, range(port_range[0], port_range[1] + 1))

    open_ports = [port for port in results if port]

    if open_ports:
        result = f"✅ Open ports on {ip}: {', '.join(map(str, open_ports))}"
    else:
        result = f"❌ No open ports found on {ip} in range {port_range[0]}-{port_range[1]}"

    print(result)
    log_result(result)
    return open_ports


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
                print(f"📜 Ports found open on {ip}: {', '.join(map(str, open_ports))}")

        elif command.startswith("vuln "):
            ip = command.split("vuln ")[1]
            score = assess_vulnerability(ip)
            print(f"🛡️ Vulnerability score for {ip}: {score} / 5")

        elif command == "exit":
            print("👋 Exiting...")
            break

        elif command == "help":
            print("\nAvailable Commands:")
            print("  ping [HOST]  - Ping a domain/IP (e.g., ping google.com)")
            print("  geo [IP]     - Get Geo-IP info (e.g., geo 8.8.8.8)")
            print("  scan [IP]    - Scan common ports on an IP (e.g., scan 192.168.1.1)")
            print("  vuln [IP]    - Assess vulnerability score for an IP (e.g., vuln 192.168.1.1)")
            print("  exit         - Exit the terminal\n")

        else:
            print("❌ Invalid command. Type 'help' for options.")


# Run the interactive terminal
interactive_terminal()
