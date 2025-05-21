import time
import socket
import requests
import psutil
import subprocess
import hashlib
import os
import base64

# Цвета для CLI
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[31m'
RESET = '\033[0m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

banner = """
                                    _
|+============================+    /|\   +===============================+|
|     _____      _____   ______   / | \   ___       ___   ______   _____  |
|    / (^) \    / ___/  / __  /  /  |  \  \  \     /  /  / ____/  /  _  \ |
|   / __  _/   / /__   / /_/ /  /   |   \  \  \   /  /  / /___   /    __/ |
|  / (__)  \  / /___  / __  /  /    |    \  \  \_/  /  / /___   /  /\ \   |
| /________/ /_____/ /_/ /_/  /_____|_____\  \_____/  /_____/  /__/  \_\  |
|                        BeaverSploit--Framework                          |
|+=======================================================================+|
"""

help_text = """ 
Available Commands:
- scan <target>          : Scan open ports on a target
- geoip <ip>             : Get geolocation data for an IP
- netstat                : Show active network connections with process names
- banner_grab <ip> <port>: Get service information from a port
- reverse_dns <ip>       : Perform reverse DNS lookup
- ping <target>          : Check host availability
- traceroute <target>    : Trace route to target
- http_headers <url>     : View HTTP headers
- dns_lookup <domain>    : Get DNS information
- subdomain_scan <domain>: Find subdomains
- ssl_scan <domain>      : Check SSL certificates
- hash_crack <hash>      : Check hash against database
- ipdata                 : Shows local and public ip
- web_scan <url>         : Show vulnerabilities of url
- help                   : Show available commands
- exit                   : Exit Beaversploit
"""

def menu():
    clear_screen()
    print(GREEN + banner + RESET)
    print("Beaversploit is a framework for security testing (educational purposes only)")
    print("Use this tool responsibly and only on systems you have permission to test")

def ipdata():
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        public_ip = requests.get("https://api64.ipify.org").text

        print(f"[+] Local IP: {local_ip}")
        print(f"[+] Public IP: {public_ip}")
    except Exception as e:
        print(f"[!] Error: {e}")

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
}

def web_scan(domain):
    """ Полноценный анализ уязвимостей веб-сайта, включая API и поддомены """

    protocol = "https://" if "https://" in domain else "http://"
    domain = domain.replace("https://", "").replace("http://", "")

    paths = [
        "/admin", "/dashboard", "/settings", "/public", "/wp-admin", "/phpinfo",
        "/assets", "/server-status", "/robots.txt"
    ]
    
    vuln_files = ["index.bak", "config.old", "database.zip", "backup.tar.gz", ".env", ".log", ".sql"]
    subdomains = ["admin", "secure", "mail", "dev"]
    api_endpoints = ["/api/v1/", "/graphql", "/rest", "/json", "/ws", "/config.json"]

    try:
        print(f"{YELLOW}[!] Scanning: {protocol}{domain}{RESET}")

        # Проверка заголовков
        response = requests.get(f"{protocol}{domain}", headers=headers, timeout=5, verify=False)
        for key, value in response.headers.items():
            if key.lower() in ["server", "x-powered-by"]:
                print(f"{GREEN}[+] Header Found: {key} -> {value}{RESET}")

        # Проверка директорий
        for path in paths:
            scan_target(f"{protocol}{domain}{path}")

        # Поиск уязвимых файлов
        for file_ext in vuln_files:
            scan_target(f"{protocol}{domain}/{file_ext}")

        # Проверка API-эндпоинтов
        for api in api_endpoints:
            scan_target(f"{protocol}{domain}{api}")

        # Проверка поддоменов
        for sub in subdomains:
            scan_target(f"{protocol}{sub}.{domain}")

    except requests.exceptions.RequestException as e:
        print(f"{RED}[!!!] Error scanning {protocol}{domain}: {e}{RESET}")

def scan_target(target):
    """ Запрос на проверку URL """
    try:
        res = requests.get(target, headers=headers, timeout=5, allow_redirects=True, verify=False)
        if res.status_code == 200:
            print(f"{GREEN}[+] Found: {target} (Status: 200){RESET}")
        elif res.status_code == 403:
            print(f"{YELLOW}[!] Forbidden: {target} (Possible WAF){RESET}")
        elif res.status_code == 404:
            print(f"[-] Not Found: {target}")
    except requests.exceptions.RequestException as e:
        print(f"{RED}[!!!] Error scanning {target}: {e}{RESET}")

def scan_ports(target):
    ports = [21, 22, 80, 443, 3306, 8080]
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex((target, port)) == 0:
                print(f"[+] Port {port} is open")

def geoip_lookup(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        print(response.json())
    except Exception as e:
        print(f"Error: {e}")

def netstat():
    try:
        print("Active Network Connections:")
        for conn in psutil.net_connections(kind='inet'):
            laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Unknown"
            raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "Unknown"
            proc_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"

            print(f"[{conn.status}] {laddr} -> {raddr} | Process: {proc_name}")
    except Exception as e:
        print(f"Error: {e}")

def banner_grab(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            sock.connect((ip, int(port)))
            sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
            banner = sock.recv(1024)
            print(banner.decode())
    except Exception as e:
        print(f"Error: {e}")

def reverse_dns(ip):
    try:
        host = socket.gethostbyaddr(ip)
        print(f"Reverse DNS result: {host}")
    except Exception as e:
        print(f"Error: {e}")

def ping(target):
    try:
        output = subprocess.check_output(f"ping -c 4 {target}", shell=True).decode()
        print(output)
    except Exception as e:
        print(f"Error: {e}")

def traceroute(target):
    try:
        output = subprocess.check_output(f"traceroute {target}", shell=True).decode()
        print(output)
    except Exception as e:
        print(f"Error: {e}")

def http_headers(url):
    try:
        response = requests.head(url)
        print(response.headers)
    except Exception as e:
        print(f"Error: {e}")

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"DNS lookup result: {ip}")
    except Exception as e:
        print(f"Error: {e}")

def subdomain_scan(domain):
    subdomains = ["www", "mail", "ftp", "api"]
    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            print(f"Found subdomain: {subdomain} -> {ip}")
        except socket.gaierror:
            pass

def ssl_scan(domain):
    try:
        response = requests.get(f"https://{domain}")
        print(response.headers.get("Strict-Transport-Security", "No SSL Headers Found"))
    except Exception as e:
        print(f"Error: {e}")

def hash_crack(hash_value):
    wordlist = ["password", "admin", "123456"]
    for word in wordlist:
        hashed = hashlib.md5(word.encode()).hexdigest()
        if hashed == hash_value:
            print(f"Hash cracked: {word}")
            return
    print("No match found.")

def terminal():
    commands = {
        "scan": scan_ports,
        "geoip": geoip_lookup,
        "netstat": netstat,
        "banner_grab": banner_grab,
        "reverse_dns": reverse_dns,
        "ping": ping,
        "traceroute": traceroute,
        "http_headers": http_headers,
        "dns_lookup": dns_lookup,
        "subdomain_scan": subdomain_scan,
        "ssl_scan": ssl_scan,
        "hash_crack": hash_crack,
        "ipdata": ipdata,
        "web_scan": web_scan,
        "help": lambda: print(help_text),
        "exit": lambda: exit()
    }

    while True:
        user_input = input(f"{YELLOW}bsf>> {RESET}").strip()
        
        if not user_input:
            continue

        args = user_input.split()
        cmd = args[0]
        params = args[1:]

        if cmd in commands:
            try:
                commands[cmd](*params)
            except TypeError:
                print(f"{YELLOW}Error: Incorrect usage of '{cmd}', check 'help'{RESET}")
        else:
            print(f"{YELLOW}Error: Command not found{RESET}")

menu()
terminal()