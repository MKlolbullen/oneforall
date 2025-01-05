# OneForAll - Comprehensive Bug Bounty/Penetration Testing Toolkit

### This is a WIP (Work In Progress)

OneForAll is an all-in-one penetration testing and reconnaissance framework designed to automate key tasks for bug bounty hunters and cybersecurity professionals. This toolkit consolidates subdomain enumeration, vulnerability assessment, directory fuzzing, and more into a cohesive workflow.


---

## Features

1. Subdomain Enumeration

Tools: assetfinder, subfinder, chaos-client

Automatically discovers subdomains and checks for live hosts.


2. URL Gathering

Tools: gau, urlfinder, katana, waybackpy, gospider

Collects URLs from various sources for deeper analysis.


3. Directory Fuzzing

Tool: gobuster

Identifies hidden directories on the target domain.


4. Vulnerability Scanning

Tools: sqlmap, dalfox, kxss, corsy, sniper, nuclei

Detects vulnerabilities such as SQL Injection, XSS, and misconfigurations.


5. Port Scanning

Tools: Nmap, Rustscan, Naabu

Comprehensive IP and port scanning for open services.


6. OSINT Gathering

Tool: Shodan API

Fetches intelligence on target IPs to reveal exposed services and metadata.


7. Reporting

Generates reports in HTML, JSON, or other formats.

Includes vulnerabilities, discovered URLs, and OSINT data.



---

## Prerequisites

System Requirements

Operating System: Linux (Ubuntu preferred)

Python Version: 3.8 or higher

Tools: Bash, curl, git


Dependencies

The following tools are required and automatically installed during setup:

assetfinder, subfinder, sqlmap, gobuster, gau, katana, dalfox, gospider, nuclei, sniper, subjack, corsy

---

Installation

1. Clone the repository:
`
git clone https://github.com/<your-username>/oneforall.git
cd oneforall
`

2. Run the setup script:
`
chmod +x setup.sh
./setup.sh
`

3. Activate the Python virtual environment:

`source oneforall-env/bin/activate`


4. Set API keys for chaos-client and Shodan during setup.



For more detailed instructions, see INSTALL.md.


---

Usage

1. Basic Command Run the script with a target domain:

`python oneforall.py -d example.com`


2. Optional Proxy Support Use the -p flag to specify a proxy:

`python oneforall.py -d example.com -p http://127.0.0.1:8080`


3. Interactive Menu The script provides interactive menus for vulnerability scanning, port scanning, and more.




---

### Output

Subdomains: subdomains.txt

URLs: urls.txt

Directories: directories.txt

Reports: example.com_report.html



---

Contribution

Contributions are welcome! Here’s how you can help:

1. Fork the repository.


2. Create a feature branch:

`git checkout -b feature-name`

3. Commit your changes:
`git commit -m 'Add new feature'`


4. Push to the branch:

`git push origin feature-name`

5. Open a pull request.

---

### License

This project is licensed under the MIT License. See the LICENSE file for details.


---

### Acknowledgments

This project integrates various open-source tools and APIs, including:

assetfinder

subfinder

sqlmap

dalfox

gobuster

katana

nuclei

sniper

Shodan API


Special thanks to the developers and maintainers of these tools for their contributions to the security community.


---
