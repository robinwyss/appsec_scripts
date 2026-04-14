# Production Promotion GO/NO-GO - Quick Reference

## Installation
```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Create Configuration
```bash
# For standalone assessment
cp config_evaluate_example.yaml my_config.yaml

# For comparative assessment (cert vs prod)
cp config_compare_example.yaml my_config.yaml
```

### 2. Edit Configuration
Update `my_config.yaml` with:
- Your Dynatrace tenant URL(s)
- Your API token(s)
- Management zones or host IDs

### 3. Run Assessment
```bash
python production_promotion_check.py -c my_config.yaml
```

## Common Commands

```bash
# Basic run with JSON output
python production_promotion_check.py -c config.yaml

# Generate CSV report
python production_promotion_check.py -c config.yaml -f csv -o report.csv

# Machine-readable output (for CI/CD)
python production_promotion_check.py -c config.yaml -m

# Verbose mode (detailed logging)
python production_promotion_check.py -c config.yaml -v

# Show help
python production_promotion_check.py -h
```

## Decision Rules

### ✅ GO Decision
- No CRITICAL/HIGH vulnerabilities
- No vulnerable functions in use
- [Compare mode] No regression vs production

### ❌ NO-GO Decision  
- Any CRITICAL/HIGH vulnerability
- Any vulnerable function in use
- Cannot assess vulnerable function usage
- [Compare mode] Regression detected

## Exit Codes
- `0` = GO (ready for production)
- `1` = NO-GO (not ready)
- `2` = Error

## CI/CD Integration
```bash
# Run and check result
python production_promotion_check.py -c config.yaml -m
if [ $? -eq 0 ]; then
    echo "✅ PROMOTING TO PRODUCTION"
else
    echo "❌ BLOCKING PROMOTION"
    exit 1
fi
```

## Files Created
- `production_promotion_check.py` - Main script
- `config_evaluate_example.yaml` - Evaluate mode template
- `config_compare_example.yaml` - Compare mode template
- `PRODUCTION_PROMOTION_GUIDE.md` - Full documentation
- `production_promotion_check.log` - Execution logs (auto-created)
- `report_<timestamp>.json` - Assessment report (auto-created)

## API Token Permissions Required
- `securityProblems.read`
- `entities.read`

## Need Help?
```bash
python production_promotion_check.py -h
```

See `PRODUCTION_PROMOTION_GUIDE.md` for comprehensive documentation.
