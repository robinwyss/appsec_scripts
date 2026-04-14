# Production Promotion GO/NO-GO Assessment Tool

## Overview

The Production Promotion GO/NO-GO Assessment Tool is a comprehensive security evaluation script that determines whether an application in a certification environment is ready for production deployment. It analyzes vulnerabilities using the Dynatrace Security API and makes data-driven decisions based on configurable criteria.

## Features

- **Dual Assessment Modes**
  - **Evaluate Mode**: Standalone assessment of certification environment
  - **Compare Mode**: Comparative analysis between certification and production environments

- **Flexible Scoping**
  - Filter by Management Zones
  - Filter by specific Host IDs
  - Mix and match between environments

- **Comprehensive Decision Logic**
  - Evaluates vulnerability severity (CRITICAL/HIGH)
  - Checks vulnerable function usage
  - Detects regressions in compare mode
  - Provides detailed reasoning for decisions

- **Multiple Output Formats**
  - JSON (detailed, hierarchical)
  - CSV (flat, spreadsheet-friendly)
  - Machine-readable (for CI/CD pipelines)

- **Rich Console Output**
  - Color-coded vulnerability digests
  - Clear decision display
  - Progress indicators

- **Detailed Logging**
  - Optional verbose mode
  - All operations logged to file
  - Debug-level details available

## Requirements

Install the required dependencies:

```bash
pip install -r requirements.txt
```

The tool requires:
- Python 3.14+
- `requests>=2.32.3`
- `pandas>=2.2.3`
- `pyyaml>=6.0.2`

## Quick Start

### 1. Create a Configuration File

Choose the appropriate template based on your needs:

**For standalone assessment (Evaluate Mode):**
```bash
cp config_evaluate_example.yaml my_config.yaml
```

**For comparative assessment (Compare Mode):**
```bash
cp config_compare_example.yaml my_config.yaml
```

Edit the configuration file with your Dynatrace environment details and API tokens.

### 2. Run the Assessment

```bash
python production_promotion_check.py -c my_config.yaml
```

### 3. Review the Results

The tool will:
- Display a colored vulnerability digest in the console
- Show the GO/NO-GO decision with reasoning
- Generate a detailed report file

## Configuration

### Evaluate Mode Configuration

```yaml
mode: evaluate

certification_environment:
  url: "https://your-tenant.live.dynatrace.com"
  token: "dt0c01.YOUR_API_TOKEN"
  verify_ssl: true
  
  scope_mode: management_zone
  management_zones:
    - "Certification - Web App"
    - "Certification - API"
```

### Compare Mode Configuration

```yaml
mode: compare

certification_environment:
  url: "https://cert-tenant.live.dynatrace.com"
  token: "dt0c01.CERT_TOKEN"
  scope_mode: management_zone
  management_zones:
    - "Cert - Application"

production_environment:
  url: "https://prod-tenant.live.dynatrace.com"
  token: "dt0c01.PROD_TOKEN"
  scope_mode: management_zone
  management_zones:
    - "Prod - Application"
```

### Scope Modes

#### Management Zone Mode
Filters vulnerabilities by Dynatrace Management Zones:

```yaml
scope_mode: management_zone
management_zones:
  - "My Management Zone 1"
  - "My Management Zone 2"
```

#### Host List Mode
Filters vulnerabilities by specific host IDs:

```yaml
scope_mode: host_list
hosts:
  - "HOST-1234567890ABCDEF"
  - "HOST-FEDCBA0987654321"
```

## Decision Logic

### GO Decision Criteria

The assessment results in a **GO** decision when ALL of the following are true:

#### Evaluate Mode:
- ✓ No CRITICAL or HIGH severity vulnerabilities
- ✓ No vulnerabilities with vulnerable functions actively in use
- ✓ All vulnerabilities have assessable vulnerable function usage (not "NOT_AVAILABLE")

#### Compare Mode (Additional):
- ✓ All Evaluate Mode criteria met
- ✓ No new vulnerabilities introduced compared to production
- ✓ No severity regressions (vulnerabilities becoming more severe)
- ✓ No vulnerable function regressions (functions becoming in-use when they weren't)

### NO-GO Decision Criteria

The assessment results in a **NO-GO** decision when ANY of the following are true:

#### Evaluate Mode:
- ✗ Any CRITICAL or HIGH severity vulnerabilities found
- ✗ Any vulnerability with vulnerable function in use
- ✗ Any vulnerability where vulnerable function usage cannot be assessed

#### Compare Mode (Additional):
- ✗ Any Evaluate Mode criteria failed
- ✗ New vulnerabilities introduced compared to production
- ✗ Severity regression detected
- ✗ Vulnerable function usage regression detected

## Decision Tree

```
┌─────────────────────────────────────┐
│   Fetch Certification Vulnerabilities   │
└──────────────┬──────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│   Check CRITICAL/HIGH Severity       │
│   Found? ──Yes──> [NO-GO]            │
└──────────────┬───────────────────────┘
               │ No
               ▼
┌──────────────────────────────────────┐
│   Check Vulnerable Functions         │
│   IN_USE or NOT_AVAILABLE? ──Yes──>  │
│   [NO-GO]                            │
└──────────────┬───────────────────────┘
               │ No
               │
        ┌──────▼────────┐
        │ Compare Mode? │
        └───┬───────┬───┘
            │ No    │ Yes
            │       │
            │       ▼
            │   ┌──────────────────────────┐
            │   │ Fetch Production Vulns   │
            │   └───────────┬──────────────┘
            │               │
            │               ▼
            │   ┌──────────────────────────┐
            │   │ Compare Environments     │
            │   │ - New vulnerabilities?   │
            │   │ - Severity regression?   │
            │   │ - Function regression?   │
            │   └───────────┬──────────────┘
            │               │
            │               ▼
            │   ┌──────────────────────────┐
            │   │ Regression? ──Yes──>     │
            │   │ [NO-GO]                  │
            │   └───────────┬──────────────┘
            │               │ No
            │               │
            └───────────────┴─────────────┐
                                          │
                                          ▼
                                   ┌──────────┐
                                   │   [GO]   │
                                   └──────────┘
```

## Command Line Options

```
python production_promotion_check.py [OPTIONS]

Required:
  -c, --config FILE       Path to YAML configuration file

Optional:
  -o, --output FILE       Output report file path
                         (default: report_<timestamp>.json)
  
  -f, --format FORMAT     Report format: json or csv
                         (default: json)
  
  -m, --machine-readable  Output only GO or NO-GO for automation
                         Suppresses detailed output
  
  -v, --verbose           Enable detailed logging to console
                         Logs all API calls and processing steps
  
  -h, --help             Show comprehensive usage guide
```

## Usage Examples

### Basic Evaluation

```bash
# Run assessment with default settings
python production_promotion_check.py -c config_evaluate.yaml
```

### Comparative Assessment with CSV Output

```bash
# Compare cert vs prod and generate CSV report
python production_promotion_check.py -c config_compare.yaml -f csv -o comparison_report.csv
```

### CI/CD Pipeline Integration

```bash
# Machine-readable output for automation
python production_promotion_check.py -c config.yaml -m

# Check exit code
if [ $? -eq 0 ]; then
    echo "GO: Proceeding with deployment"
else
    echo "NO-GO: Blocking deployment"
    exit 1
fi
```

### Verbose Debugging

```bash
# Enable detailed logging for troubleshooting
python production_promotion_check.py -c config.yaml -v
```

### Custom Report Location

```bash
# Specify custom output file
python production_promotion_check.py -c config.yaml -o /path/to/reports/assessment_$(date +%Y%m%d).json
```

## Exit Codes

The script uses exit codes for automation and CI/CD integration:

- **0**: GO decision - Application is ready for production
- **1**: NO-GO decision - Application is NOT ready for production
- **2**: Error in execution (configuration issue, API error, etc.)

## Output Formats

### JSON Report Structure

```json
{
  "assessment_info": {
    "mode": "compare",
    "timestamp": "2025-12-04T10:30:00",
    "decision": "GO",
    "summary": "✓ GO Decision: ..."
  },
  "certification_environment": {
    "total_vulnerabilities": 5,
    "vulnerabilities": [
      {
        "vulnerability_id": "...",
        "cve_id": "CVE-2024-12345",
        "title": "Critical SQL Injection",
        "risk_assessment": {
          "riskLevel": "MEDIUM",
          "riskScore": 6.5,
          "vulnerableFunctionUsage": "NOT_IN_USE"
        },
        "affected_entities": [...],
        "management_zones": [...]
      }
    ]
  },
  "production_environment": { ... },
  "comparison": {
    "new_vulnerabilities_count": 0,
    "resolved_vulnerabilities_count": 2,
    "severity_regression": false,
    "vulnerable_function_regression": false
  },
  "decision_details": { ... }
}
```

### CSV Report Structure

The CSV format provides a flattened view suitable for spreadsheet analysis:

| Environment | CVE_ID | Title | Risk_Level | Risk_Score | Vulnerable_Function_Usage | ... |
|-------------|--------|-------|------------|------------|---------------------------|-----|
| CERTIFICATION | CVE-2024-12345 | SQL Injection | MEDIUM | 6.5 | NOT_IN_USE | ... |
| PRODUCTION | CVE-2024-67890 | XSS Vulnerability | LOW | 3.2 | NOT_IN_USE | ... |

## Dynatrace API Token Permissions

Your API tokens require the following permissions:

- **securityProblems.read** - Read security problems
- **entities.read** - Read entities (hosts, processes, management zones)

### Creating an API Token

1. Navigate to **Settings > Integration > Dynatrace API**
2. Click **Generate token**
3. Provide a name (e.g., "Production Promotion Assessment")
4. Enable required scopes:
   - `securityProblems.read`
   - `entities.read`
5. Click **Generate token**
6. Copy and securely store the token

## Logging

### Console Output

By default, the tool provides:
- Progress indicators during API calls
- Color-coded vulnerability digest
- Decision summary with reasoning

### File Logging

All operations are logged to `production_promotion_check.log`:
- API calls and responses
- Decision logic steps
- Error details

### Verbose Mode

Enable with `-v` flag for detailed console output:
```bash
python production_promotion_check.py -c config.yaml -v
```

Includes:
- API call details
- Filtering logic
- Comparative analysis steps
- Debug-level information

## Troubleshooting

### Common Issues

#### "Configuration file not found"
- Verify the path to your configuration file
- Use absolute paths if relative paths fail

#### "API request failed"
- Check API token permissions
- Verify tenant URL is correct (include https://)
- Confirm token is not expired
- Check network connectivity

#### "No vulnerabilities found"
- Verify management zone names are exact matches
- Check host IDs are correct
- Confirm entities exist in the specified timeframe
- Try verbose mode to see API responses

#### "Import yaml could not be resolved"
- Install PyYAML: `pip install pyyaml>=6.0.2`
- Update requirements.txt if needed

### Debug Mode

Run with verbose logging to diagnose issues:

```bash
python production_promotion_check.py -c config.yaml -v > debug_output.txt 2>&1
```

Check `production_promotion_check.log` for detailed information.

## Integration Examples

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Assessment') {
            steps {
                script {
                    def result = sh(
                        script: 'python production_promotion_check.py -c config.yaml -m',
                        returnStatus: true
                    )
                    
                    if (result == 0) {
                        echo "GO: Security assessment passed"
                    } else {
                        error "NO-GO: Security assessment failed"
                    }
                }
            }
        }
    }
}
```

### GitHub Actions

```yaml
name: Production Promotion Check

on:
  push:
    branches: [ release/* ]

jobs:
  security-assessment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.14'
      
      - name: Install dependencies
        run: pip install -r requirements.txt
      
      - name: Run GO/NO-GO Assessment
        run: |
          python production_promotion_check.py -c config.yaml -m
          echo "Assessment result: $?"
      
      - name: Upload Report
        uses: actions/upload-artifact@v2
        if: always()
        with:
          name: security-report
          path: report_*.json
```

### GitLab CI

```yaml
security_assessment:
  stage: test
  script:
    - pip install -r requirements.txt
    - python production_promotion_check.py -c config.yaml -m
  artifacts:
    paths:
      - report_*.json
    when: always
  only:
    - /^release/.*$/
```

## Advanced Configuration

### Multi-Environment Setup

You can maintain multiple configuration files for different scenarios:

```bash
configs/
├── prod_promotion_webapp.yaml
├── prod_promotion_api.yaml
└── prod_promotion_full.yaml
```

Run specific assessments:
```bash
python production_promotion_check.py -c configs/prod_promotion_webapp.yaml
```

### Automated Reporting

Generate timestamped reports automatically:

```bash
#!/bin/bash
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="/reports/security"

python production_promotion_check.py \
    -c config.yaml \
    -o "${REPORT_DIR}/assessment_${TIMESTAMP}.json" \
    -v
```

## Best Practices

1. **Use Management Zones** for logical grouping of applications
2. **Store API tokens securely** using environment variables or secret managers
3. **Run assessments regularly** in your CI/CD pipeline
4. **Review NO-GO decisions carefully** before overriding
5. **Keep configuration files in version control** (without tokens)
6. **Archive reports** for compliance and audit trails
7. **Use Compare Mode** when promoting from cert to prod
8. **Enable verbose logging** when troubleshooting

## Security Considerations

- **Never commit API tokens** to version control
- Use **environment variables** for sensitive data:
  ```yaml
  token: "${DYNATRACE_API_TOKEN}"
  ```
- Restrict API token permissions to **minimum required**
- Rotate API tokens regularly
- Use **separate tokens** for each environment in compare mode

## Contributing

To extend or modify the tool:

1. Review `dynatrace_api.py` for available API methods
2. Follow the existing code structure
3. Add new decision criteria in the `_make_decision()` method
4. Update documentation for new features

## Support

For issues or questions:

1. Check the troubleshooting section
2. Review log files with verbose mode enabled
3. Verify configuration against examples
4. Contact your Dynatrace support team

## Version History

- **1.0.0** (2025-12-04)
  - Initial release
  - Evaluate and Compare modes
  - Management Zone and Host List scoping
  - JSON and CSV output formats
  - Machine-readable output for CI/CD
  - Comprehensive decision logic

## License

Copyright © 2025 Dynatrace. All rights reserved.
