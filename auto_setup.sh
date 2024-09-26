#!/bin/bash

# Determine OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [[ "$EUID" -ne 0 ]]; then
        echo "Please run as root (use sudo)"
        exit
    fi
    update_cmd="sudo apt-get update"
    install_cmd="sudo apt-get install -y"
    pip_install="python3-pip"
    gcc_install="build-essential"
    openssl_install="libssl-dev"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # Checking for Homebrew installation
    if ! command -v brew &>/dev/null; then
        echo "Homebrew not installed. Please install Homebrew."
        exit 1
    fi
    update_cmd="brew update"
    install_cmd="brew install"
    gcc_install="gcc"
    openssl_install="openssl@3"
else
    echo "Unsupported operating system."
    exit 1
fi

# Update package lists
echo "Updating package lists..."
$update_cmd

# Install pip
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "Installing pip..."
    $install_cmd $pip_install
fi

# Install Python dependencies using pip
echo "Installing Python dependencies..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    # Ensure pip3 is used without sudo on macOS
    pip3 install --user ecdsa coincurve pynacl
else
    sudo pip3 install ecdsa coincurve pynacl
fi

# Install GCC for compiling C++ code
echo "Installing GCC..."
$install_cmd $gcc_install

# Install OpenSSL for cryptographic operations
echo "Installing OpenSSL..."
$install_cmd $openssl_install

echo "All dependencies installed successfully. You can now run the e-SeaFL system."
