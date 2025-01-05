# OneForAll - Penetration Testing Toolkit

**OneForAll** is a comprehensive penetration testing and reconnaissance framework designed for bug bounty hunters and security professionals. It automates various tasks like subdomain enumeration, vulnerability scanning, and reporting, combining multiple open-source tools into one cohesive workflow.

## Features

- **Subdomain Enumeration**: Utilize tools like `assetfinder`, `subfinder`, and `chaos-client`.
- **Domain Live Check**: Verifies which subdomains are live.
- **Directory Fuzzing**: Identifies hidden directories using `gobuster`.
- **Vulnerability Scanning**:
  - SQL Injection Detection with `sqlmap`.
  - XSS Scanning with `dalfox`, `kxss`, and `XXStrike`.
  - CORS Misconfiguration Detection with `corsy`.
- **Web Technology Fingerprinting**: Tools like `whatweb` and `wappalyzer` are integrated.
- **Port Scanning**: Supports `Nmap`, `Rustscan`, and `Naabu`.
- **OSINT Gathering**: Fetches intelligence using the Shodan API.
- **Automated Reporting**: Generates reports in HTML, JSON, and other formats.

## Prerequisites

### System Requirements
- **Python**: 3.8 or higher
- **Tools**: Ensure the following tools are installed on your system:
  - `assetfinder`
  - `subfinder`
  - `sqlmap`
  - `gobuster`
  - `gau`
  - `nmap`
  - `whatweb`
  - `dalfox`

### Python Dependencies
Install Python dependencies using `pip`:

```bash
pip install -r requirements.txt
```

## Environment Variables

Set the following environment variables for API keys:

CHAOS_CLIENT_KEY: Your Chaos API key.

SHODAN_API_KEY: Your Shodan API key.


Example:

`
export CHAOS_CLIENT_KEY="your_chaos_api_key"
export SHODAN_API_KEY="your_shodan_api_key"
`
# Usage

Basic Command

Run the script with the target domain:

`
python oneforall.py -d example.com
`

### Optional Proxy Support

Add a proxy with the -p flag:

`
python oneforall.py -d example.com -p http://127.0.0.1:8080
`

## Output

The script generates various output files:

subdomains.txt: List of discovered subdomains.

Reports in multiple formats (e.g., HTML, JSON).


#### Example Workflow

1. Enumerate subdomains for example.com:

`
python oneforall.py -d example.com
`

2. Check which subdomains are live and perform directory fuzzing.


3. Scan for vulnerabilities using integrated tools.


4. Generate an HTML report for the findings.

---

## Contributing

Contributions are welcome! Feel free to fork the repository, make enhancements, and submit a pull request. Please ensure your code adheres to the following:

PEP 8 coding standards.

Includes proper error handling and logging.


## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

This tool integrates the capabilities of various open-source tools and APIs. Special thanks to the creators of assetfinder, subfinder, sqlmap, dalfox, and others.


---

Happy Hunting!

---
