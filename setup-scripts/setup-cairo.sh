#!/bin/bash

# Install Python 3.9.15 using pyenv, if not already installed
pyenv install -s 3.9.15
pyenv local 3.9.15
# Set the Python version and create a virtual environment
PYENV_VERSION=3.9.15 python -m venv snos-env

# Activate the virtual environment and install the dependencies
source snos-env/bin/activate
pip install -r requirements.txt
