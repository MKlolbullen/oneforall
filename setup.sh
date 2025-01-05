#!/bin/bash

# OneForAll Setup Script
# This script installs necessary tools, sets environment variables, creates a Python virtual environment, and installs dependencies.

echo "Setting up OneForAll environment..."

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update and install essential tools
echo "Updating and installing dependencies..."
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl nmap jq build-essential

# Install Go for tools requiring Go environment
if ! command_exists go; then
    echo "Installing Go..."
    wget https://go.dev/dl/go1.20.5.linux-amd64.tar.gz -O go.tar.gz
    sudo tar -C /usr/local -xzf go.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >>~/.bashrc
    source ~/.bashrc
    rm go.tar.gz
else
    echo "Go is already installed."
fi

# Install required tools
echo "Installing required tools..."
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/hahwul/dalfox/v2@latest
git clone https://github.com/sqlmapproject/sqlmap.git ~/sqlmap
git clone https://github.com/haccer/subjack.git ~/subjack
cd ~/subjack && go build && sudo mv subjack /usr/local/bin && cd ~
pip3 install waybackpy

# Set environment variables
echo "Setting up environment variables..."
read -p "Enter your Chaos API key: " chaos_key
read -p "Enter your Shodan API key: " shodan_key

echo "export CHAOS_CLIENT_KEY=\"$chaos_key\"" >>~/.bashrc
echo "export SHODAN_API_KEY=\"$shodan_key\"" >>~/.bashrc
source ~/.bashrc

# Create Python virtual environment and install dependencies
echo "Creating Python virtual environment..."
python3 -m venv oneforall-env
source oneforall-env/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
deactivate

echo "Setup complete! To activate the virtual environment, use:"
echo "source oneforall-env/bin/activate"
