#!/usr/bin/env python3
"""
OneForAll - Comprehensive Penetration Testing Toolkit

Consolidates subdomain enumeration, URL gathering, vulnerability scanning,
IP/port scanning, OSINT, and reporting into a single script with additional tools.
"""

import os
import sys
import logging
import requests
import shutil
import json
import subprocess
import argparse
import concurrent.futures
import tempfile
import webbrowser
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Load configuration from environment variables
CHAOS_CLIENT_KEY = os.getenv("CHAOS_CLIENT_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# -------------------------------------------------------------------
# 1. Helper Functions
# -------------------------------------------------------------------

def check_required_tools():
    """
    Ensure required external tools are installed.
    Add any additional tools here that you rely on.
    """
    required_tools = [
        "assetfinder", "subfinder", "chaos-client", "sqlmap", "gobuster",
        "gau", "nmap", "whatweb", "dalfox", "kxss", "corsy", "gospider",
        "katana", "waybackpy", "nuclei", "sniper", "subjack", "urlfinder"
    ]
    missing_tools = [tool for tool in required_tools if shutil.which(tool) is None]

    if missing_tools:
        logger.error(f"Missing the following required tools: {', '.join(missing_tools)}")
        logger.error("Please install them before running this script.")
        sys.exit(1)


def run_command(command, error_message, env=None):
    """
    Run a shell command, capturing output and returning it as a string.
    On error, logs the error output.

    Args:
        command (str): The command to run.
        error_message (str): The error message to display if it fails.
        env (dict): Optional environment variables to use.

    Returns:
        str | None: The command output on success, or None on failure.
    """
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, env=env)
        return result.decode().strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"{error_message}\n{e.output.decode().strip()}")
        return None


# -------------------------------------------------------------------
# 2. Subdomain Enumeration
# -------------------------------------------------------------------

def enum_subs(domain, proxy=None):
    """
    Enumerate subdomains using assetfinder, subfinder, chaos-client, subjack, etc.

    Args:
        domain (str): Target domain.
        proxy (str): Proxy server URL if any.

    Returns:
        list: A sorted list of discovered subdomains.
    """
    env = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None
    subdomains = set()

    # Temporary file to collect subdomains
    with tempfile.NamedTemporaryFile(delete=False, mode="w+") as tmpfile:
        tmp_name = tmpfile.name

    # assetfinder
    run_command(f"assetfinder {domain} >> {tmp_name}", "Error running assetfinder.", env)

    # subfinder
    run_command(f"subfinder -d {domain} -all -silent >> {tmp_name}", "Error running subfinder.", env)

    # chaos-client
    if CHAOS_CLIENT_KEY:
        run_command(
            f"chaos-client -d {domain} -key {CHAOS_CLIENT_KEY} >> {tmp_name}",
            "Error running chaos-client.", env
        )
    else:
        logger.warning("CHAOS_CLIENT_KEY not set; skipping chaos-client.")

    # Read and filter results
    with open(tmp_name, "r") as file:
        for line in file:
            sub = line.strip()
            if sub:
                subdomains.add(sub)

    # subjack can be used to detect subdomain takeovers, but it also can discover subdomains
    # We'll run subjack on the subdomains we already have to check for takeover possibility.
    with open("enum_subdomains.txt", "w") as file:
        file.write("\n".join(subdomains) + "\n")

    # Subjack scanning (for takeover vulnerabilities)
    # For simplicity, we won’t add new subdomains to the list from subjack,
    # but you can adapt this if subjack uncovers additional ones.
    takeover_output = run_command(
        "subjack -w enum_subdomains.txt -t 100 -ssl -v -c fingerprints.json -o subjack_results.txt -a",
        "Error running subjack.",
        env
    )
    if takeover_output:
        logger.info("Subjack completed. Results saved to subjack_results.txt")

    # Clean up
    os.unlink(tmp_name)

    subdomains = sorted(subdomains)
    logger.info(f"Found {len(subdomains)} subdomains for {domain}.")
    return subdomains


def check_domain(domain, proxy=None):
    """
    Check if a domain is live by sending a GET request.

    Args:
        domain (str): The domain to check.
        proxy (str): Proxy if any.

    Returns:
        bool: True if the domain is live, else False.
    """
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        response = requests.get(f"http://{domain}", timeout=5, proxies=proxies)
        return response.status_code == 200
    except requests.RequestException:
        return False


# -------------------------------------------------------------------
# 3. Directory Fuzzing
# -------------------------------------------------------------------

def directory_fuzzing(domain, proxy=None):
    """
    Perform directory fuzzing using gobuster.

    Args:
        domain (str): Target domain to fuzz.
        proxy (str): Optional proxy.
    """
    env = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None
    wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"  # Adjust as needed

    command = (
        f"gobuster dir -u http://{domain} -w {wordlist} "
        f"-o {domain}_directories.txt"
    )
    if proxy:
        command += f" --proxy {proxy}"

    run_command(command, f"Error fuzzing directories for {domain}", env)


# -------------------------------------------------------------------
# 4. URL Gathering
# -------------------------------------------------------------------

def url_gathering(domain, proxy=None):
    """
    Gather URLs using various tools: gau, urlfinder, waybackpy, gospider, katana, JSFinder, LinkFinder, etc.

    Args:
        domain (str): Target domain.
        proxy (str): Optional proxy.

    Returns:
        list: A list of unique URLs found.
    """
    env = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None
    all_urls = set()

    # Temporary file to collect URLs
    with tempfile.NamedTemporaryFile(delete=False, mode="w+") as tmpfile:
        tmp_name = tmpfile.name

    # gau
    run_command(f"gau {domain} >> {tmp_name}", "Error running gau.", env)

    # urlfinder
    run_command(f"urlfinder -d {domain} >> {tmp_name}", "Error running urlfinder.", env)

    # waybackpy (we'll just store as well)
    # waybackpy typically is run as `waybackpy --url <domain> --json`, or it can be used as a library.
    run_command(f"waybackpy --url {domain} --raw-url --limit 5000 >> {tmp_name}", "Error running waybackpy", env)

    # gospider
    run_command(f"gospider -d 2 -s http://{domain} >> {tmp_name}", "Error running gospider.", env)

    # katana
    run_command(f"katana -u http://{domain} -d 3 -jc -jsl -silent >> {tmp_name}", "Error running katana.", env)

    # JSFinder & LinkFinder typically parse JS files for links, but for demonstration:
    # JSFinder
    run_command(f"python3 JSFinder.py -u http://{domain} >> {tmp_name}", "Error running JSFinder.", env)
    # LinkFinder
    run_command(f"python3 linkfinder.py -i http://{domain} -o cli >> {tmp_name}", "Error running LinkFinder.", env)

    # Collect URLs
    with open(tmp_name, "r") as file:
        for line in file:
            line = line.strip()
            if line and line.startswith("http"):
                all_urls.add(line)

    # Clean up
    os.unlink(tmp_name)

    all_urls = sorted(all_urls)
    with open(f"{domain}_urls.txt", "w") as f:
        for url in all_urls:
            f.write(url + "\n")

    logger.info(f"Gathered {len(all_urls)} URLs for {domain}.")
    return all_urls


# -------------------------------------------------------------------
# 5. Vulnerability Scanning
# -------------------------------------------------------------------

def sqlmap_scan(domain, proxy=None):
    """
    Run sqlmap on the gathered URLs.

    Args:
        domain (str): The domain to scan.
        proxy (str): The proxy to use.
    """
    env = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None
    # We expect {domain}_urls.txt to exist
    urlfile = f"{domain}_urls.txt"
    # Example: only scan URLs that contain typical query params
    # You can customize the grep as needed
    command = (
        f"cat {urlfile} | grep '=' | sort -u | "
        f"xargs -I{{}} sqlmap --batch --random-agent -u {{}} "
    )
    if proxy:
        command += f" --proxy {proxy}"

    run_command(command, "Error running sqlmap scan.", env)


def corsy_scan(domain, proxy=None):
    """
    Run corsy to detect CORS issues.

    Args:
        domain (str): Target domain.
        proxy (str): Optional proxy.
    """
    env = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None
    # corsy -u http://example.com
    command = f"corsy -u http://{domain}"
    if proxy:
        command += f" --proxy {proxy}"

    run_command(command, f"Error running corsy for {domain}", env)


def xxstrike_scan(domain, proxy=None):
    """
    Run XXStrike (XXS) to detect XSS vulnerabilities.

    Args:
        domain (str): Target domain.
        proxy (str): Optional proxy.
    """
    env = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None
    command = f"xxs -u http://{domain}"
    if proxy:
        command += f" --proxy {proxy}"

    run_command(command, f"Error running XXStrike for {domain}", env)


def dalfox_scan(domain, proxy=None):
    """
    Run dalfox to detect XSS vulnerabilities.

    Args:
        domain (str): Target domain.
        proxy (str): Optional proxy.
    """
    env = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None
    command = f"dalfox url http://{domain}"
    if proxy:
        command += f" --proxy {proxy}"

    run_command(command, f"Error running dalfox for {domain}", env)


def kxss_scan(domain, proxy=None):
    """
    Run kxss to detect XSS vulnerabilities.

    Args:
        domain (str): Target domain.
        proxy (str): Optional proxy.
    """
    env = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None
    command = f"kxss -u http://{domain}"
    if proxy:
        command += f" --proxy {proxy}"

    run_command(command, f"Error running kxss for {domain}", env)


def sniper_scan(domain, proxy=None, custom=None):
    """
    Run Sniper for vulnerability scanning.

    Args:
        domain (str): Target domain.
        proxy (str): Optional proxy.
        custom (str): Additional custom flags.
    """
    env = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None
    # Basic usage: sn1per <domain>
    cmd = f"sniper -t {domain} -o sniper_{domain}"
    if custom:
        cmd += f" {custom}"
    output = run_command(cmd, f"Error running Sniper on {domain}", env)
    if output:
        logger.info(f"Sniper results for {domain} saved to sniper_{domain}/")


def nuclei_scan(domain, proxy=None, template=None):
    """
    Run Nuclei for vulnerability scanning with optional template.

    Args:
        domain (str): Target domain.
        proxy (str): Optional proxy.
        template (str): Path to a custom Nuclei template or template directory.
    """
    env = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None
    cmd = f"nuclei -u http://{domain}"
    if template:
        cmd += f" -t {template}"

    run_command(cmd, f"Error running nuclei on {domain}", env)


def vulnerability_scanner(domain, proxy=None):
    """
    Consolidated vulnerability scanning menu.
    """
    logger.info("Starting vulnerability scanner menu...")
    print(f"{Fore.CYAN}Vulnerability Scanner Menu:{Style.RESET_ALL}")
    print("1. Sn1per (default)")
    print("2. Sn1per (custom)")
    print("3. Nuclei (default templates)")
    print("4. Nuclei (custom templates)")
    print("5. CORSy")
    print("6. XXStrike")
    print("7. Dalfox")
    print("8. kxss")
    choice = input("Enter your choice: ")

    if choice == "1":
        sniper_scan(domain, proxy)
    elif choice == "2":
        custom_opts = input("Enter custom Sn1per flags: ")
        sniper_scan(domain, proxy, custom_opts)
    elif choice == "3":
        nuclei_scan(domain, proxy)
    elif choice == "4":
        template_path = input("Enter path to custom Nuclei templates: ")
        nuclei_scan(domain, proxy, template_path)
    elif choice == "5":
        corsy_scan(domain, proxy)
    elif choice == "6":
        xxstrike_scan(domain, proxy)
    elif choice == "7":
        dalfox_scan(domain, proxy)
    elif choice == "8":
        kxss_scan(domain, proxy)
    else:
        logger.warning("Invalid choice.")


# -------------------------------------------------------------------
# 6. IP and Port Scanning
# -------------------------------------------------------------------

def nmap_scan(target, port_range, proxy=None):
    """
    Run Nmap to scan the target.

    Args:
        target (str): The target to scan.
        port_range (str): The port range (e.g. '1-1000').
        proxy (str): The proxy (not supported by nmap directly).
    """
    # Nmap does not support proxies natively.
    logger.info("Running Nmap scan without proxy.")
    command = f"nmap -p {port_range} {target} -oN {target}_nmap_scan.txt"
    run_command(command, f"Error running Nmap on {target}")


def rustscan_scan(target, port_range, proxy=None):
    """
    Run Rustscan to scan the target.

    Args:
        target (str): The target to scan.
        port_range (str): The port range.
        proxy (str): The proxy (not supported by rustscan).
    """
    logger.info("Running Rustscan scan without proxy.")
    # Typically usage: rustscan --ulimit 5000 -a <target> -r <range> ...
    command = f"rustscan -a {target} -r {port_range} -oN {target}_rustscan_scan.txt"
    run_command(command, f"Error running Rustscan on {target}")


def naabu_scan(target, port_range, proxy=None):
    """
    Run Naabu to scan the target.

    Args:
        target (str): The target to scan.
        port_range (str): The port range.
        proxy (str): The proxy (not supported by naabu).
    """
    logger.info("Running Naabu scan without proxy.")
    command = f"naabu -host {target} -p {port_range} -o {target}_naabu_scan.txt"
    run_command(command, f"Error running Naabu on {target}")


def ip_port_scanner(domain, subdomains, proxy=None):
    """
    Perform IP and port scanning using Nmap, Rustscan, or Naabu.

    Args:
        domain (str): The domain to scan.
        subdomains (list): List of discovered subdomains.
        proxy (str): Optional proxy (Nmap, Rustscan, Naabu do not directly support proxies).
    """
    print(f"{Fore.CYAN}IP and Port Scanner Menu:{Style.RESET_ALL}")
    print("1. Nmap")
    print("2. Rustscan")
    print("3. Naabu")
    tool_choice = input("Enter your choice (1-3): ")

    if tool_choice not in ["1", "2", "3"]:
        logger.warning("Invalid choice.")
        return

    print(f"{Fore.CYAN}Scan Target Menu:{Style.RESET_ALL}")
    print("1. Domain Only")
    print("2. Domain + Subdomains")
    print("3. Custom IP")
    target_choice = input("Enter your choice (1-3): ")

    # Build target
    if target_choice == "1":
        target = domain
    elif target_choice == "2":
        # We can pass subdomains, but each scanner might handle them differently
        # Nmap: you can pass multiple targets space-separated
        # For demonstration, let's just pass them space-separated
        target = " ".join(subdomains)
    elif target_choice == "3":
        target = input("Enter IP address or CIDR: ")
    else:
        logger.warning("Invalid choice.")
        return

    port_range = input("Enter port range (e.g. 1-1000): ")
    if not port_range:
        port_range = "1-1000"

    if tool_choice == "1":
        nmap_scan(target, port_range, proxy)
    elif tool_choice == "2":
        rustscan_scan(target, port_range, proxy)
    elif tool_choice == "3":
        naabu_scan(target, port_range, proxy)


# -------------------------------------------------------------------
# 7. OSINT (Shodan)
# -------------------------------------------------------------------

def osint_gathering(ip):
    """
    Gather OSINT data using Shodan API.

    Args:
        ip (str): The IP address.

    Returns:
        dict: OSINT data from Shodan.
    """
    if not SHODAN_API_KEY:
        logger.warning("SHODAN_API_KEY not set, skipping OSINT gathering.")
        return {}

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        logger.error(f"Error gathering OSINT data for {ip}: {e}")
        return {}


# -------------------------------------------------------------------
# 8. Reporting
# -------------------------------------------------------------------

def generate_html_report(report_data, domain):
    """
    Generate an HTML report.

    Args:
        report_data (dict): Data to include in the report.
        domain (str): The scanned domain.
    """
    filename = f"{domain}_report.html"
    with open(filename, "w") as f:
        f.write("<html><head><title>OneForAll Report</title></head><body>\n")
        f.write(f"<h1>Penetration Test Report for {domain}</h1>\n")

        # Subdomains
        if "subdomains" in report_data:
            f.write("<h2>Discovered Subdomains</h2>\n<ul>\n")
            for sd in report_data["subdomains"]:
                f.write(f"<li>{sd}</li>\n")
            f.write("</ul>\n")

        # URLs
        if "urls" in report_data:
            f.write("<h2>Discovered URLs</h2>\n<ul>\n")
            for url in report_data["urls"]:
                f.write(f"<li>{url}</li>\n")
            f.write("</ul>\n")

        # OSINT
        if "osint" in report_data:
            f.write("<h2>OSINT Data</h2>\n<pre>\n")
            f.write(json.dumps(report_data["osint"], indent=4))
            f.write("</pre>\n")

        # Vulnerabilities
        if "vulnerabilities" in report_data:
            f.write("<h2>Vulnerability Findings</h2>\n<ul>\n")
            for vuln in report_data["vulnerabilities"]:
                f.write(f"<li>{vuln}</li>\n")
            f.write("</ul>\n")

        f.write("</body></html>\n")

    logger.info(f"HTML report generated: {filename}")
    # Optionally open in browser
    try:
        webbrowser.open(filename)
    except:
        pass


# -------------------------------------------------------------------
# 9. Main
# -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="OneForAll - Comprehensive Pentesting Toolkit")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-p", "--proxy", help="Optional proxy (e.g. http://127.0.0.1:8080)")
    args = parser.parse_args()

    domain = args.domain
    proxy = args.proxy

    # Check required tools
    check_required_tools()

    logger.info(f"Starting OneForAll for domain: {domain}")

    # Enumerate subdomains
    subdomains = enum_subs(domain, proxy)

    # Check which subdomains are live (multi-threaded)
    live_subdomains = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_sub = {executor.submit(check_domain, sd, proxy): sd for sd in subdomains}
        for future in concurrent.futures.as_completed(future_to_sub):
            sub = future_to_sub[future]
            if future.result():
                live_subdomains.append(sub)

    # Directory fuzzing on main domain
    directory_fuzzing(domain, proxy)

    # URL gathering
    urls = url_gathering(domain, proxy)

    # Optional SQL injection scanning
    sqlmap_scan(domain, proxy)

    # Additional vulnerability scanning (interactive menu)
    vulnerability_scanner(domain, proxy)

    # OSINT gathering on subdomains' IP addresses
    osint_data = {}
    for sd in live_subdomains:
        try:
            ip_out = run_command(f"dig +short {sd}", "Error running dig.")
            ip_address = ip_out.strip() if ip_out else None
            if ip_address:
                osint_data[sd] = osint_gathering(ip_address)
        except Exception as e:
            logger.error(f"OSINT error for subdomain {sd}: {e}")

    # Prepare data for reporting
    # (You can fill in more details, vulnerabilities, etc.)
    report_data = {
        "subdomains": subdomains,
        "urls": urls,
        "vulnerabilities": [
            # Example placeholders
            "Potential XSS on /search",
            "Potential SQLi on /login"
        ],
        "osint": osint_data
    }

    # Generate minimal HTML report
    generate_html_report(report_data, domain)

    # IP/Port scanning menu
    ip_port_scanner(domain, subdomains, proxy)

    logger.info("All done! Happy hunting.")


if __name__ == "__main__":
    main()
