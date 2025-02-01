#!/bin/bash

# Get Python version (major.minor)
PYTHON_VERSION=$(python3 -c 'import sys; print("python" + ".".join(map(str, sys.version_info[:2])))')

VENV="ta-lib-venv"
TA_LIB=$(whereis ta-lib | awk '{print $2}')

# Check if ta-lib is installed
if [ -n "$TA_LIB" ]; then
    echo "ta-lib is already installed at $TA_LIB"
else
    echo "Installing ta-lib..."
    wget https://github.com/ta-lib/ta-lib/releases/download/v0.6.4/ta-lib_0.6.4_amd64.deb
    sudo dpkg -i ta-lib_0.6.4_amd64.deb
    rm ta-lib_0.6.4_amd64.deb
fi

# Install required dependencies using the Python version variable
sudo apt-get update
sudo apt-get install -y "$PYTHON_VERSION"-tk "$PYTHON_VERSION"-dev libatlas-base-dev "$PYTHON_VERSION"-venv

# Create and activate virtual environment
python3 -m venv "$VENV"
source "$VENV/bin/activate"

# Install Python dependencies
pip install --upgrade pip
pip install -r src/requirements.txt
