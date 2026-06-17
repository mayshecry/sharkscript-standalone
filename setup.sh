#!/bin/bash

# SharkScript Environment Setup
set -e

echo "Updating system..."
sudo apt-get update -y && sudo apt-get install -y wget git gcc

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo "Go not found. Downloading Go 1.21.5..."
    wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    rm go1.21.5.linux-amd64.tar.gz
    
    # Update profile
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
    export PATH=$PATH:/usr/local/go/bin
    echo "Go installed successfully."
else
    echo "Go is already installed: $(go version)"
fi

# Compile SharkScript
echo "Compiling SharkScript..."
if [ ! -f "main.go" ]; then
    echo "Error: Run this script from the sharkscript-src root directory."
    exit 1
fi

go build -o shs main.go

# Install as 'shs'
echo "Installing 'shs' to /usr/local/bin..."
sudo mv shs /usr/local/bin/shs
sudo chmod +x /usr/local/bin/shs

echo "------------------------------------------------"
echo "Setup Complete!"
echo "You can now use 'shs --compile' or 'shs --run'"
echo "------------------------------------------------"


if command -v shs &> /dev/null; then
    echo "Verification: shs is active."
else
    echo "Please restart your terminal or run: source ~/.profile"
fi
