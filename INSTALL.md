INSTALL.md

# Installation Guide for OneForAll

This guide provides step-by-step instructions for setting up the OneForAll penetration testing toolkit.

---

## Prerequisites

### System Requirements
- **Operating System**: Linux (Ubuntu recommended)
- **Python Version**: 3.8 or higher
- **Tools**: Bash, curl, git

### Dependencies
The following tools will be installed automatically:
- `assetfinder`
- `subfinder`
- `gobuster`
- `dalfox`
- `gau`
- `katana`
- `subjack`
- `sqlmap`
- `Sn1per`
- Python libraries (specified in `requirements.txt`)

---

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/<your-username>/oneforall.git
   cd oneforall

2. Run the Setup Script Run the provided setup.sh script to install all dependencies and set up your environment.
`
chmod +x setup.sh
./setup.sh
`

3. Activate the Virtual Environment After installation, activate the Python virtual environment:
`
source oneforall-env/bin/activate
`

4. Set API Keys During setup, you'll be prompted to enter your Chaos API key and Shodan API key. These are required for subdomain enumeration and OSINT gathering.




---

Usage

1. Run the Script Once the environment is set up, run the main script:
`
python oneforall.py -d example.com
`

2. Optional Proxy Support Use the -p flag to specify a proxy:
`
python oneforall.py -d example.com -p http://127.0.0.1:8080
`



---

Troubleshooting

Ensure you have Go installed and its path added to your ~/.bashrc:
`
export PATH=$PATH:/usr/local/go/bin
`
For missing dependencies, rerun the setup.sh script.
