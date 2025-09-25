#!/bin/bash

# Install Python 3.9.20 using pyenv, if not already installed
pyenv install -s 3.9.20
pyenv local 3.9.20
# Set the Python version and create a virtual environment
PYENV_VERSION=3.9.20 python -m venv venv

# Activate the virtual environment and install the dependencies
source venv/bin/activate
pip install -r requirements.txt
