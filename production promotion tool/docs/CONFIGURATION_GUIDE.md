# Production Promotion Check - Configuration Guide

## Overview

The Production Promotion Check script provides fine-grained control over security assessments through exclusion mechanisms and configurable thresholds. This guide explains how to customize the tool's behavior for your specific use case.

## Configuration Structure

The configuration file uses YAML format and includes the following main sections:

```yaml
mode: compare  # or 'evaluate'
max_workers: 20  # Concurrent API requests
assessment_rules:  # NEW: Exclusion and threshold configuration
  excluded_cves: []
  severity_exclusions: {}
  thresholds: {}
certification_environment: {}
production_environment: {}  # Required for compare mode
```

## Assessment Rules

### 1. CVE Exclusions

Exclude specific CVEs from all security assessments. Use this for:
- **False positives**: CVEs that don't apply to your environment
- **Accepted risks**: Documented security exceptions
- **Compensating controls**: Vulnerabilities mitigated by other measures

```yaml
assessment_rules:
  excluded_cves:
    - "CVE-2023-44487"  # HTTP/2 Rapid Reset - mitigated by WAF
    - "CVE-2024-12345"  # Accepted risk with documented justification
```

**Behavior**: Vulnerabilities with these CVEs will be completely filtered out and won't affect any decision criteria.

### 2. Severity-Based Exclusions

Skip specific security checks for vulnerabilities at certain severity levels.

**Available Checks**:
- `vulnerable_function`: Skip check for vulnerable function in use
- `severity_regression`: Skip severity increase comparison (compare mode)
- `new_vulnerabilities`: Skip counting as new vulnerability (compare mode)

**Available Severity Levels**:
- `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`

```yaml
assessment_rules:
  severity_exclusions:
    MEDIUM:
      - vulnerable_function  # Don't fail on MEDIUM vulns with functions in use
    LOW:
      - vulnerable_function
      - severity_regression  # Don't fail on LOW severity increases
```

**Use Cases**:

**Development/Staging Environment**:
```yaml
severity_exclusions:
  MEDIUM:
    - vulnerable_function
  LOW:
    - vulnerable_function
    - severity_regression
```

**Production (Conservative)**:
```yaml
severity_exclusions:
  LOW:
    - vulnerable_function  # Only exclude LOW severity
```

### 3. Decision Thresholds

Configure GO/NO-GO decision criteria.

#### Maximum Allowed Severity

Block promotion if vulnerabilities at or above this level exist.

```yaml
assessment_rules:
  thresholds:
    max_allowed_severity: HIGH  # Blocks on CRITICAL and HIGH
```

Options:
- `CRITICAL`: Only block on CRITICAL vulnerabilities
- `HIGH`: Block on CRITICAL and HIGH (default, recommended for production)
- `MEDIUM`: Block on CRITICAL, HIGH, and MEDIUM
- `LOW`: Block on any severity above NONE
- `NONE`: Block on any vulnerability

#### Maximum New Vulnerabilities

(Compare mode only) Limit how many new vulnerabilities are acceptable.

```yaml
assessment_rules:
  thresholds:
    max_new_vulnerabilities: 10  # Allow up to 10 new vulnerabilities
```

Values:
- `-1`: Unlimited (default) - no limit on new vulnerabilities
- `0`: Zero tolerance - block on any new vulnerability
- `N`: Allow up to N new vulnerabilities

#### Allow Vulnerable Functions for Severities

Permit vulnerabilities with functions in use for specific severity levels.

```yaml
assessment_rules:
  thresholds:
    allow_vulnerable_function_for_severities:
      - LOW
      - MEDIUM  # Allow MEDIUM and LOW with vulnerable functions in use
```

**Difference from severity_exclusions**:
- `severity_exclusions.vulnerable_function`: Completely skip the check (not evaluated)
- `allow_vulnerable_function_for_severities`: Check is performed but doesn't block promotion

## Configuration Examples

### Scenario 1: Strict Production Security (Default)

Maximum security posture - suitable for production environments with zero tolerance.

```yaml
assessment_rules:
  excluded_cves: []  # No exclusions
  severity_exclusions: {}  # All checks apply
  thresholds:
    max_allowed_severity: HIGH  # Block on CRITICAL/HIGH
    max_new_vulnerabilities: -1
    allow_vulnerable_function_for_severities: []  # No vulnerable functions allowed
```

**Criteria**:
- No CRITICAL or HIGH severity vulnerabilities
- No vulnerable functions in use at any severity
- Tracks all severity regressions
- No limit on new vulnerabilities (but they're tracked)

### Scenario 2: Balanced Security (Recommended)

Pragmatic approach - strict on high severity, relaxed on lower severity.

```yaml
assessment_rules:
  excluded_cves:
    - "CVE-2023-44487"  # Known false positive in environment
  
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

**Criteria**:
- No CRITICAL or HIGH severity vulnerabilities
- No vulnerable functions in use for CRITICAL/HIGH
- MEDIUM/LOW vulnerabilities with functions in use are acceptable
- LOW severity increases are acceptable

### Scenario 3: Development/Testing Environment

Relaxed rules - suitable for non-production environments.

```yaml
assessment_rules:
  excluded_cves:
    - "CVE-2023-12345"  # Test data vulnerability
    - "CVE-2024-67890"  # Dev tool vulnerability
  
  severity_exclusions:
    HIGH:
      - severity_regression
    MEDIUM:
      - vulnerable_function
      - severity_regression
    LOW:
      - vulnerable_function
      - severity_regression
  
  thresholds:
    max_allowed_severity: MEDIUM  # Allow HIGH (but track it)
    max_new_vulnerabilities: 20
    allow_vulnerable_function_for_severities:
      - LOW
      - MEDIUM
```

**Criteria**:
- Only blocks on CRITICAL and MEDIUM (HIGH is allowed)
- Up to 20 new vulnerabilities accepted
- Vulnerable functions allowed for LOW/MEDIUM
- Severity regressions ignored for HIGH/MEDIUM/LOW

### Scenario 4: Pre-Production Validation

Strict on critical issues, flexible on operational concerns.

```yaml
assessment_rules:
  excluded_cves: []
  
  severity_exclusions:
    MEDIUM:
      - vulnerable_function
  
  thresholds:
    max_allowed_severity: HIGH
    max_new_vulnerabilities: 5  # Allow up to 5 new vulnerabilities
    allow_vulnerable_function_for_severities:
      - LOW
```

**Criteria**:
- No CRITICAL or HIGH severity vulnerabilities
- Up to 5 new vulnerabilities tolerated
- Vulnerable functions acceptable for LOW and MEDIUM
- All severity regressions tracked

## Output Changes

### Vulnerability Digest

The vulnerability digest now includes CVE information:

```
Vulnerability Digest:

  • Denial of Service (DoS)
    CVE: CVE-2023-44487
    Davis Security Score: 8.7 | Severity: HIGH
    Vulnerable Function: NOT_AVAILABLE

  • Improper Input Validation
    CVE: Unknown CVE
    Davis Security Score: 4.3 | Severity: MEDIUM
    Vulnerable Function: IN_USE
```

**CVE Display**:
- If CVE IDs exist: Lists all CVEs (e.g., "CVE-2023-44487, CVE-2024-12345")
- If no CVE: Shows "Unknown CVE" in orange

### Decision Logic

The tool respects exclusions when making GO/NO-GO decisions:

```
Checking vulnerable functions...
  → Skipping vulnerable function check for MEDIUM severity (excluded)
  → Found 5 HIGH severity vulnerabilities with vulnerable functions in use

Checking severity regressions...
  → Skipping severity regression check for CVE-2023-XXX at LOW severity (excluded)
  → Found 2 severity regressions (HIGH severity)
```

## Migration Guide

### Updating Existing Configurations

If you have an existing configuration file, add the `assessment_rules` section:

**Before**:
```yaml
mode: compare
max_workers: 20
certification_environment:
  # ...
```

**After**:
```yaml
mode: compare
max_workers: 20
assessment_rules:  # ADD THIS SECTION
  excluded_cves: []
  severity_exclusions: {}
  thresholds:
    max_allowed_severity: HIGH
    max_new_vulnerabilities: -1
    allow_vulnerable_function_for_severities: []
certification_environment:
  # ...
```

**Backward Compatibility**: If `assessment_rules` is missing, the tool uses default strict settings (no exclusions).

### Testing Your Configuration

1. **Start with defaults**: Begin with strict settings
2. **Run assessment**: Execute the tool and review results
3. **Identify issues**: Note false positives or overly strict rules
4. **Add exclusions**: Add specific CVEs or severity exclusions
5. **Re-run assessment**: Verify the changes work as expected
6. **Document decisions**: Comment your exclusions with justification

## Best Practices

### 1. Document Exclusions

Always comment why a CVE is excluded:

```yaml
excluded_cves:
  - "CVE-2023-44487"  # HTTP/2 Rapid Reset - WAF protection in place
                       # See security review SR-2024-001
```

### 2. Use Severity Exclusions Sparingly

Prefer specific CVE exclusions over broad severity exclusions:

✅ **Good**:
```yaml
excluded_cves:
  - "CVE-2024-12345"  # Specific false positive
```

❌ **Avoid**:
```yaml
severity_exclusions:
  HIGH:
    - vulnerable_function  # Too broad
```

### 3. Review Exclusions Regularly

Periodically review excluded CVEs:
- Have security conditions changed?
- Are compensating controls still in place?
- Can the exclusion be removed?

### 4. Different Configs for Different Environments

Maintain separate configurations:
- `config_production.yaml`: Strict rules
- `config_staging.yaml`: Balanced rules
- `config_development.yaml`: Relaxed rules

### 5. Version Control

Store configuration files in version control:
- Track changes over time
- Require approval for exclusion changes
- Link to security review documentation

## Troubleshooting

### Issue: Too Many Failures

**Symptom**: Every assessment results in NO-GO

**Solutions**:
1. Review severity distribution: `max_allowed_severity: CRITICAL`
2. Add known false positives to `excluded_cves`
3. Exclude vulnerable function checks for lower severities

### Issue: Exclusions Not Applied

**Symptom**: Excluded CVEs still causing failures

**Checks**:
1. Verify YAML syntax is correct
2. Check CVE ID exact match (case-sensitive)
3. Review logs with `-v` flag for debug messages

### Issue: Unexpected GO Decision

**Symptom**: Expected NO-GO but got GO

**Checks**:
1. Verify exclusions aren't too broad
2. Check if `max_allowed_severity` is set too high
3. Review `allow_vulnerable_function_for_severities` settings

## Reference

### Complete Configuration Schema

```yaml
mode: compare | evaluate
max_workers: <number>

assessment_rules:
  excluded_cves:
    - "<CVE-ID>"
  
  severity_exclusions:
    <SEVERITY>:  # CRITICAL, HIGH, MEDIUM, LOW, NONE
      - vulnerable_function
      - severity_regression
      - new_vulnerabilities
  
  thresholds:
    max_allowed_severity: CRITICAL | HIGH | MEDIUM | LOW | NONE
    max_new_vulnerabilities: <number> | -1
    allow_vulnerable_function_for_severities:
      - <SEVERITY>

certification_environment:
  url: "<dynatrace-url>"
  token: "<api-token>"
  verify_ssl: true | false
  scope_mode: management_zone | host_list
  management_zones: [<list>]
  hosts: [<list>]

production_environment:  # Required for compare mode
  # Same structure as certification_environment
```

### Check Evaluation Order

1. **CVE Exclusion**: Filter out excluded CVEs first
2. **Severity Check**: Evaluate max_allowed_severity
3. **Vulnerable Function Check**: Apply with severity exclusions
4. **Regression Checks** (compare mode):
   - New vulnerabilities (with severity exclusions)
   - Severity regression (with severity exclusions)
   - Vulnerable function regression (with severity exclusions)

### Exit Codes

- `0`: GO decision - safe to promote
- `1`: NO-GO decision - promotion blocked
- `2`: Error - configuration or API issue
