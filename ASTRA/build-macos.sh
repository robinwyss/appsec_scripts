#!/bin/bash
# Build ASTRA for macOS (must run on macOS)

set -e

echo "Building ASTRA for macOS..."

# Install dependencies if needed
pip install -r requirements.txt pyinstaller

cd ASTRA

# Build universal binary (works on both Intel and ARM)
pyinstaller --onefile \
  --name astra-macos \
  --add-data "config.example.yaml:." \
  --hidden-import=dynatrace_api \
  --collect-all reportlab \
  --target-arch universal2 \
  astra_report.py

echo "✓ macOS build complete: dist/astra-macos"
