#!/bin/bash
echo "Installing FindAndFixMe Dependencies for WSL/Linux..."

# Ensure pip is up-to-date
python3 -m pip install --upgrade pip

# Install requirements via pip
python3 -m pip install -r requirements.txt

echo ""
echo "Installation Complete!"
echo "If Atheris fails to install, try installing clang/LLVM first: sudo apt-get install clang llvm"
