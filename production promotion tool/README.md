# Production Promotion Tool

A comprehensive tool for making GO/NO-GO decisions on production promotions based on security vulnerability assessments in Dynatrace environments.

## Overview

This tool evaluates security vulnerabilities to determine if an application is ready for production promotion. It supports two operational modes:

- **Evaluate Mode**: Standalone assessment of a certification environment
- **Compare Mode**: Comparative assessment between certification and production environments

## Quick Start

```bash
# Evaluate certification environment
python production_promotion_check.py -c examples/config_evaluate_example.yaml

# Compare certification vs production
python production_promotion_check.py -c examples/config_compare_example.yaml

# Machine-readable output for CI/CD
python production_promotion_check.py -c examples/config_evaluate_example.yaml -m
```

## Documentation

- **[Production Promotion Guide](docs/PRODUCTION_PROMOTION_GUIDE.md)**: Comprehensive usage guide
- **[Configuration Guide](docs/CONFIGURATION_GUIDE.md)**: Configuration options and settings
- **[Quick Start Guide](docs/QUICKSTART.md)**: Quick reference for common tasks
- **[Exclusions Reference](docs/EXCLUSIONS_QUICK_REFERENCE.md)**: Vulnerability exclusion features

## Directory Structure

```
production promotion tool/
├── production_promotion_check.py    # Main script
├── docs/                            # Documentation
│   ├── PRODUCTION_PROMOTION_GUIDE.md
│   ├── CONFIGURATION_GUIDE.md
│   ├── QUICKSTART.md
│   └── ...
├── examples/                        # Configuration examples
│   ├── config_evaluate_example.yaml
│   ├── config_compare_example.yaml
│   └── ...
└── tests/                          # Test infrastructure
    ├── run_tests.py
    └── tempconfig/
```

## Features

- **Flexible Severity Thresholds**: Set maximum allowed severity levels
- **Vulnerability Exclusions**: Exclude specific CVEs or patterns
- **Machine-Readable Output**: CI/CD integration with exit codes
- **Comparative Analysis**: Compare security posture across environments
- **Detailed Reporting**: JSON reports with comprehensive vulnerability data
- **Process Group Filtering**: Focus on specific applications or services

## Requirements

- Python 3.6+
- Dynatrace API access with security problem permissions
- Required Python packages (see main repository requirements.txt)

## Exit Codes

- `0`: GO - Safe to promote to production
- `1`: NO-GO - Vulnerabilities exceed thresholds
- `2`: Error - Configuration or API issues

## Version

1.0.0
