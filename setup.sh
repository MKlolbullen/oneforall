#!/bin/bash

# Script to set up OneForAll environment

# Function to install tools
install_tools() {
    echo "Installing required tools..."
    # Update and install necessary tools
    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv git curl nmap
    echo "Installing assetfinder..."
    go install github.com/tomnomnom/assetfinder@latest
    echo "Installing subfinder..."
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    echo "Installing sqlmap..."
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
    echo "Installing gobuster..."
    go install github.com/OJ/gobuster/v3@latest
    echo "Installing gau..."
    go install github.com/lc/gau/v2/cmd/gau@latest
    echo "Installing whatweb..."
    sudo apt install -y whatweb
    echo "Installing dalfox..."
    go install github.com/hahwul/dalfox/v2@latest
}

# Function to set environment variables
set_env_vars() {
    echo "Setting up environment variables..."
    read -p "Enter your Chaos API key: " chaos_key
    read -p "Enter your Shodan API key: " shodan_key

    echo "export CHAOS_CLIENT_KEY=\"$chaos_key\"" >> ~/.bashrc
    echo "export SHODAN_API_KEY=\"$shodan_key\"" >> ~/.bashrc

    source ~/.bashrc
    echo "Environment variables set."
}

# Function to create Python virtual environment and install dependencies
setup_virtualenv() {
    echo "Creating Python virtual environment..."
    python3 -m venv oneforall-env
    source oneforall-env/bin/activate
    echo "Installing Python dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
    echo "Python virtual environment is ready."
}

# Main script execution
echo "Setting up OneForAll environment..."

install_tools
set_env_vars
setup_virtualenv

echo "Setup complete. Activate your virtual environment with:"
echo "source oneforall-env/bin/activate"
