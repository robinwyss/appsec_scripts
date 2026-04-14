# Configuration Exclusions - Quick Reference

## Summary of New Features

The production promotion check tool now supports comprehensive exclusion mechanisms to provide fine-grained control over security assessments.

## Quick Start

Add this section to your config file:

```yaml
assessment_rules:
  excluded_cves:
    - "CVE-2023-44487"  # Your excluded CVE
  
  severity_exclusions:
    MEDIUM:
      - vulnerable_function
    LOW:
      - vulnerable_function
      - severity_regression
  
  thresholds:
    max_allowed_severity: HIGH
    max_new_vulnerabilities: -1
    allow_vulnerable_function_for_severities: []
```

## Key Features

### 1. Exclude Specific CVEs
```yaml
excluded_cves:
  - "CVE-2023-44487"  # Completely filter out this CVE
```

### 2. Skip Checks by Severity
```yaml
severity_exclusions:
  MEDIUM:
    - vulnerable_function  # Don't check vulnerable functions for MEDIUM
  LOW:
    - vulnerable_function
    - severity_regression
```

Available checks:
- `vulnerable_function`: Skip vulnerable function in use check
- `severity_regression`: Skip severity increase check (compare mode)
- `new_vulnerabilities`: Skip counting as new vulnerability (compare mode)

### 3. Configure Thresholds
```yaml
thresholds:
  max_allowed_severity: HIGH  # Block on CRITICAL/HIGH
  max_new_vulnerabilities: 10  # Allow up to 10 new vulns
  allow_vulnerable_function_for_severities: [LOW, MEDIUM]
```

## Common Scenarios

### Strict (Default)
```yaml
assessment_rules:
  excluded_cves: []
  severity_exclusions: {}
  thresholds:
    max_allowed_severity: HIGH
    max_new_vulnerabilities: -1
    allow_vulnerable_function_for_severities: []
```

### Balanced (Recommended)
```yaml
assessment_rules:
  excluded_cves: []
  severity_exclusions:
    MEDIUM:
      - vulnerable_function
    LOW:
      - vulnerable_function
      - severity_regression
  thresholds:
    max_allowed_severity: HIGH
    max_new_vulnerabilities: -1
    allow_vulnerable_function_for_severities: []
```

### Relaxed (Development)
```yaml
assessment_rules:
  excluded_cves:
    - "CVE-2023-12345"  # Test environment issue
  severity_exclusions:
    MEDIUM:
      - vulnerable_function
      - severity_regression
    LOW:
      - vulnerable_function
      - severity_regression
  thresholds:
    max_allowed_severity: MEDIUM
    max_new_vulnerabilities: 20
    allow_vulnerable_function_for_severities: [LOW, MEDIUM]
```

## New Output Features

### Vulnerability Digest Now Shows CVEs

Before:
```
  • Denial of Service (DoS)
    Davis Security Score: 8.7 | Severity: HIGH
    Vulnerable Function: NOT_AVAILABLE
```

After:
```
  • Denial of Service (DoS)
    CVE: CVE-2023-44487
    Davis Security Score: 8.7 | Severity: HIGH
    Vulnerable Function: NOT_AVAILABLE
```

Or if no CVE available:
```
  • Improper Input Validation
    CVE: Unknown CVE
    Davis Security Score: 4.3 | Severity: MEDIUM
    Vulnerable Function: IN_USE
```

## Files

- `config_example_with_exclusions.yaml` - Complete example config with all options
- `CONFIGURATION_GUIDE.md` - Comprehensive documentation (70+ pages)
- `my_config.yaml` - Updated with assessment_rules structure

## Testing Your Configuration

1. Add `assessment_rules` section to your config
2. Run with verbose mode: `python production_promotion_check.py -c config.yaml -v`
3. Check logs for exclusion messages:
   ```
   Excluding vulnerability S-XXX - CVE in exclusion list: ['CVE-2023-44487']
   Skipping vulnerable function check for MEDIUM severity (excluded)
   ```

## Documentation

See `CONFIGURATION_GUIDE.md` for:
- Detailed explanation of each option
- Multiple configuration scenarios
- Best practices
- Troubleshooting guide
- Migration guide for existing configs

## Backward Compatibility

If `assessment_rules` is missing from config, the tool uses default strict settings:
- No excluded CVEs
- No severity exclusions
- Default thresholds (HIGH severity, unlimited new vulnerabilities)

Existing configs will continue to work without modification.
