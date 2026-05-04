#!/bin/bash
echo "Installing FindAndFixMe Dependencies for WSL/Linux (C++ Migration)..."

# 1. Install C++ Dependencies (LLVM 16, Clang, Z3, CMake, AFL++)
echo "Installing System Dependencies (Requires sudo)..."
sudo apt-get update
sudo apt-get install -y cmake build-essential python3-dev
sudo apt-get install -y llvm-16 clang-16 libclang-16-dev
sudo apt-get install -y libz3-dev z3
sudo apt-get install -y afl++

# 2. Python Dependencies
echo "Installing Python API & Frontend Dependencies..."
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt

# 3. Build Core C++ Engine
echo "Building C++ Core Engine (MutationEngine)..."
cd core
mkdir -p build
cd build
cmake ..
make

echo ""
echo "Installation Complete!"
echo "To start the system, open two terminals:"
echo "1. uvicorn frontend.api:app --reload (FastAPI Backend)"
echo "2. streamlit run frontend/app.py (Streamlit Frontend)"
