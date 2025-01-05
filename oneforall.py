def nmap_scan(target, port_range, proxy=None):
    """
    Run Nmap to scan the target.
    
    Args:
        target (str): The target to scan.
        port_range (str): The port range to scan (e.g., 1-1000).
        proxy (str): The proxy to use.
    
    Returns:
        None
    """
    try:
        if proxy:
            print(f"{Fore.RED}Nmap does not support proxy settings directly. Running without proxy.{Style.RESET_ALL}")
        subprocess.run(["nmap", "-p", port_range, target, "-oN", f"{target}_nmap_scan.txt"], check=True)
        print(f"{Fore.GREEN}Nmap scan complete. Results saved to {target}_nmap_scan.txt{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running Nmap: {e}{Style.RESET_ALL}")

def rustscan_scan(target, port_range, proxy=None):
    """
    Run Rustscan to scan the target.
    
    Args:
        target (str): The target to scan.
        port_range (str): The port range to scan (e.g., 1-1000).
        proxy (str): The proxy to use.
    
    Returns:
        None
    """
    try:
        if proxy:
            print(f"{Fore.RED}Rustscan does not support proxy settings directly. Running without proxy.{Style.RESET_ALL}")
        ulimit = input("Enter the ulimit value (e.g., 5000) or press Enter to use default: ") or "5000"
        subprocess.run(["rustscan", "--ulimit", ulimit, "-t", target, "-r", port_range, "-oN", f"{target}_rustscan_scan.txt"], check=True)
        print(f"{Fore.GREEN}Rustscan scan complete. Results saved to {target}_rustscan_scan.txt{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running Rustscan: {e}{Style.RESET_ALL}")

def naabu_scan(target, port_range, proxy=None):
    """
    Run Naabu to scan the target.
    
    Args:
        target (str): The target to scan.
        port_range (str): The port range to scan (e.g., 1-1000).
        proxy (str): The proxy to use.
    
    Returns:
        None
    """
    try:
        if proxy:
            print(f"{Fore.RED}Naabu does not support proxy settings directly. Running without proxy.{Style.RESET_ALL}")
        subprocess.run(["naabu", "-host", target, "-p", port_range, "-o", f"{target}_naabu_scan.txt"], check=True)
        print(f"{Fore.GREEN}Naabu scan complete. Results saved to {target}_naabu_scan.txt{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running Naabu: {e}{Style.RESET_ALL}")

def vulnerability_scanner(domain, proxy=None):
    try:
        print(f"{Fore.CYAN}Vulnerability Scanner Menu:{Style.RESET_ALL}")
        print("1. Run Sniper with default settings")
        print("2. Run Sniper with custom settings")
        print("3. Run XSRFProbe")
        print("4. Run CORSy")
        print("5. Run XXStrike")
        print("6. Run Dalfox")
        print("7. Run kxss")
        choice = input("Enter your choice: ")
        if choice == "1":
            if proxy:
                subprocess.run(f"sn1per --output sniper_{domain}.txt {domain} --proxy {proxy}", shell=True, check=True)
            else:
                subprocess.run(f"sn1per --output sniper_{domain}.txt {domain}", shell=True, check=True)
        elif choice == "2":
            custom_settings = input("Enter custom settings for Sniper (e.g. -t 1337 -p 80): ")
            if proxy:
                subprocess.run(f"sn1per --output sniper_{domain}.txt {domain} {custom_settings} --proxy {proxy}", shell=True, check=True)
            else:
                subprocess.run(f"sn1per --output sniper_{domain}.txt {domain} {custom_settings}", shell=True, check=True)
        elif choice == "3":
            if proxy:
                subprocess.run(f"xsrfprobe -u {domain} --proxy {proxy}", shell=True, check=True)
            else:
                subprocess.run(f"xsrfprobe -u {domain}", shell=True, check=True)
        elif choice == "4":
            corsy_scan(domain, proxy)
        elif choice == "5":
            xxstrike_scan(domain, proxy)
        elif choice == "6":
            dalfox_scan(domain, proxy)
        elif choice == "7":
            kxss_scan(domain, proxy)
        else:
            print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running vulnerability scanner: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="BBHunter")
    parser.add_argument("-d", "--domain", help="The domain to scan", required=True)
    parser.add_argument("-p", "--proxy", help="The proxy to use", default=None)
    args = parser.parse_args()

    print(f"{Fore.GREEN}Welcome to BBHunter{Style.RESET_ALL}\n\n")
    target_domain = args.domain
    proxy = args.proxy

    subdomains = enum_subs(target_domain, proxy)
    sorted_subdomains = sort_doms(subdomains)
    print(f"{Fore.CYAN}Sorted and unique subdomains:{Style.RESET_ALL}")
    for subdomain in sorted_subdomains:
        print(subdomain)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        for subdomain in sorted_subdomains:
            futures.append(executor.submit(check_domain, subdomain, proxy))
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                print(f"{Fore.GREEN}{future.result()} is live.{Style.RESET_ALL}")

    directory_fuzzing(target_domain, proxy)
    unique_urls = url_gathering(target_domain, proxy)
    sqlmap_scan(target_domain, proxy)

    webtech_scan(target_domain, sorted_subdomains, proxy)
    vulnerability_scanner(target_domain, proxy)

    for subdomain in sorted_subdomains:
        try:
            ip = subprocess.check_output(["dig", "+short", subdomain]).strip().decode()
            if ip:
                osint_data = osint_gathering(ip)
                print(json.dumps(osint_data, indent=4))
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Error getting IP address for {subdomain}: {e}{Style.RESET_ALL}")

    # Collect data for the report
    vulnerabilities = [
        {"name": "SQL Injection", "rank": "High", "cve": "CVE-2021-1234"},
        {"name": "XSS", "rank": "Medium", "cve": "CVE-2021-5678"},
        # Add more vulnerabilities as needed
    ]
    osint_data = {}
    for subdomain in sorted_subdomains:
        try:
            ip = subprocess.check_output(["dig", "+short", subdomain]).strip().decode()
            if ip:
                osint_data[subdomain] = osint_gathering(ip)
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Error getting IP address for {subdomain}: {e}{Style.RESET_ALL}")

    report_data = {
        "vulnerabilities": vulnerabilities,
        "osint": osint_data
    }

    print(f"{Fore.CYAN}Report Generation Menu:{Style.RESET_ALL}")
    print("1. HTML")
    print("2. PDF")
    print("3. CSV")
    print("4. JSON")
    print("5. TXT")
    report_format = input("Enter your choice: ")

    if report_format == "1":
        generate_report(report_data, target_domain, "html")
    elif report_format == "2":
        generate_report(report_data, target_domain, "pdf")
    elif report_format == "3":
        generate_report(report_data, target_domain, "csv")
    elif report_format == "4":
        generate_report(report_data, target_domain, "json")
    elif report_format == "5":
        generate_report(report_data, target_domain, "txt")
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

    # IP and Port Scanning
    ip_port_scanner(target_domain, sorted_subdomains, proxy)

if __name__ == "__main__":
    main()
