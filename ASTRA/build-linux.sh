#!/bin/bash
# Build ASTRA for Linux using Docker (can run on any platform)

set -e

echo "Building ASTRA for Linux x64..."

docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace/ASTRA \
  python:3.11-slim \
  bash -c "
    pip install --no-cache-dir -r requirements.txt pyinstaller && \
    pyinstaller --onefile \
      --name astra-linux-x64 \
      --add-data 'config.example.yaml:.' \
      --hidden-import=dynatrace_api \
      --collect-all reportlab \
      astra_report.py
  "

echo "✓ Linux build complete: ASTRA/dist/astra-linux-x64"
