import os
import sys
import logging
import requests
import subprocess
import json
import argparse
import concurrent.futures
import tempfile
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# Load configuration from environment variables
CHAOS_CLIENT_KEY = os.getenv("CHAOS_CLIENT_KEY", "your_chaos_client_key_here")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "your_shodan_api_key_here")

if not CHAOS_CLIENT_KEY or not SHODAN_API_KEY:
    logger.error("Please set CHAOS_CLIENT_KEY and SHODAN_API_KEY in your environment variables.")
    sys.exit(1)


def check_tool_availability():
    """Ensure required tools are installed."""
    required_tools = ["assetfinder", "subfinder", "sqlmap", "gobuster", "gau", "nmap", "whatweb", "dalfox"]
    missing_tools = [tool for tool in required_tools if not shutil.which(tool)]

    if missing_tools:
        logger.error(f"The following tools are required but not installed: {', '.join(missing_tools)}")
        sys.exit(1)


def run_command(command, error_message, env=None):
    """
    Run a shell command and handle errors.

    Args:
        command (str): The command to run.
        error_message (str): The error message to display if the command fails.
        env (dict): Optional environment variables.

    Returns:
        str: Command output.
    """
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, env=env)
        return result.decode().strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"{error_message}\n{e.output.decode().strip()}")
        return None


def check_domain(domain, proxy=None):
    """
    Check if a domain is live by sending a GET request.

    Args:
        domain (str): The domain to check.
        proxy (str): The proxy to use.

    Returns:
        bool: True if the domain is live, False otherwise.
    """
    try:
        proxies = {"http": proxy, "https": proxy} if proxy else None
        response = requests.get(f"http://{domain}", timeout=5, proxies=proxies)
        return response.status_code == 200
    except requests.RequestException as e:
        logger.warning(f"Error checking domain {domain}: {e}")
        return False


def enumerate_subdomains(domain, proxy=None):
    """
    Enumerate subdomains using assetfinder, subfinder, and chaos-client.

    Args:
        domain (str): The domain to enumerate subdomains for.
        proxy (str): The proxy to use.

    Returns:
        list: A list of subdomains.
    """
    subdomains = set()
    env = {"http_proxy": proxy, "https_proxy": proxy} if proxy else None

    commands = [
        f"assetfinder {domain}",
        f"subfinder -d {domain} -silent",
        f"chaos-client -d {domain} -key {CHAOS_CLIENT_KEY}"
    ]

    with tempfile.NamedTemporaryFile(delete=False, mode="w+") as tmpfile:
        for command in commands:
            output = run_command(f"{command} >> {tmpfile.name}", f"Failed to enumerate subdomains with {command}.", env)
            if output:
                logger.info(f"Subdomains found with {command}:\n{output}")

        tmpfile.seek(0)
        subdomains.update(line.strip() for line in tmpfile if line.strip())

    os.unlink(tmpfile.name)
    return sorted(subdomains)


def save_to_file(data, filename):
    """Save data to a file."""
    with open(filename, "w") as file:
        file.writelines(f"{line}\n" for line in data)
    logger.info(f"Data saved to {filename}")


def generate_report(data, domain, format="html"):
    """
    Generate a report in the specified format.

    Args:
        data (dict): The data to include in the report.
        domain (str): The domain being scanned.
        format (str): The format of the report (html, pdf, csv, json, txt).

    Returns:
        str: Path to the generated report.
    """
    report_path = f"{domain}_report.{format}"
    if format == "html":
        with open(report_path, "w") as file:
            file.write("<html><head><title>Scan Report</title></head><body>")
            file.write(f"<h1>Scan Report for {domain}</h1>")
            file.write("<ul>")
            for vuln in data.get("vulnerabilities", []):
                file.write(f"<li>{vuln}</li>")
            file.write("</ul></body></html>")
    elif format == "json":
        with open(report_path, "w") as file:
            json.dump(data, file, indent=4)
    else:
        logger.error("Unsupported report format.")
        return None

    logger.info(f"Report generated: {report_path}")
    return report_path


def main():
    parser = argparse.ArgumentParser(description="OneForAll - Penetration Testing Toolkit")
    parser.add_argument("-d", "--domain", required=True, help="The domain to scan.")
    parser.add_argument("-p", "--proxy", help="Optional proxy to use.")
    args = parser.parse_args()

    domain = args.domain
    proxy = args.proxy

    logger.info(f"Starting scan for domain: {domain}")
    subdomains = enumerate_subdomains(domain, proxy)
    save_to_file(subdomains, "subdomains.txt")

    report_data = {
        "subdomains": subdomains,
        "vulnerabilities": []  # Add vulnerability data here.
    }
    generate_report(report_data, domain, format="html")


if __name__ == "__main__":
    check_tool_availability()
    main()

