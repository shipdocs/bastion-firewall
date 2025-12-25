#!/bin/bash
# Test runner for Bastion Firewall
# Ensures dependencies are installed before running tests

set -e

echo "=== Bastion Firewall Test Runner ==="

# Check if virtual environment exists, create if not
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install test dependencies
echo "Installing test dependencies..."
pip install -r test-requirements.txt

# Run the tests
echo "Running tests..."
python -m pytest tests/ -v --cov=bastion --cov-report=term-missing

echo "Tests completed successfully!"