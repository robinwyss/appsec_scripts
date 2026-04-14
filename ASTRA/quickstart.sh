#!/bin/bash
# ASTRA Quick Start Script

echo "============================================"
echo "  ASTRA - Quick Start"
echo "============================================"
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python version: $PYTHON_VERSION"

# Check if in correct directory
if [ ! -f "ASTRA/astra_report.py" ]; then
    echo "❌ Error: Please run this script from the appsec_scripts directory"
    exit 1
fi

echo ""
echo "Step 1: Installing dependencies..."
pip3 install -q -r ASTRA/requirements.txt
echo "✓ Dependencies installed"

echo ""
echo "Step 2: Configuration setup..."
if [ ! -f "ASTRA/config.yaml" ]; then
    cp ASTRA/config.example.yaml ASTRA/config.yaml
    echo "✓ Created config.yaml from template"
    echo ""
    echo "⚠️  ACTION REQUIRED:"
    echo "   1. Edit ASTRA/config.yaml with your Dynatrace details"
    echo "   2. Set your API token: export DT_API_TOKEN='your-token'"
    echo ""
    read -p "Press Enter when ready to continue..."
else
    echo "✓ config.yaml already exists"
fi

echo ""
echo "Step 3: Validating configuration..."
if [ -z "$DT_API_TOKEN" ]; then
    echo "❌ DT_API_TOKEN environment variable not set"
    echo "   Set it with: export DT_API_TOKEN='your-token'"
    exit 1
else
    echo "✓ DT_API_TOKEN is set"
fi

echo ""
echo "Step 4: Creating reports directory..."
mkdir -p ASTRA/reports
echo "✓ Reports directory ready"

echo ""
echo "============================================"
echo "  Ready to run ASTRA!"
echo "============================================"
echo ""
echo "Run Phase 1 assessment (default):"
echo "  python3 ASTRA/astra_report.py -c ASTRA/config.yaml"
echo ""
echo "With explicit phase flag:"
echo "  python3 ASTRA/astra_report.py -c ASTRA/config.yaml --phase-1"
echo ""
echo "With debug output:"
echo "  python3 ASTRA/astra_report.py -c ASTRA/config.yaml --debug"
echo ""
echo "Phase 2 (coming soon):"
echo "  python3 ASTRA/astra_report.py -c ASTRA/config.yaml --phase-2"
echo ""
