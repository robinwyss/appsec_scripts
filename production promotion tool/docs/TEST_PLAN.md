# Production Promotion Check - Test Plan

## Test Infrastructure
- Test configs location: `tempconfig/`
- Test results: Documented in test execution output
- Base config: Uses real Dynatrace environments for integration testing

## Test Categories

### 1. Configuration Parsing Tests
- **TEST-001**: Valid configuration parsing
- **TEST-002**: Empty severity_exclusions (regression test)
- **TEST-003**: CVE exclusions parsing
- **TEST-004**: Threshold values parsing

### 2. GO/NO-GO Decision Tests

#### Compare Mode Tests
- **TEST-101**: GO - No vulnerabilities in cert, none in prod
- **TEST-102**: GO - Same vulnerabilities in both environments
- **TEST-103**: GO - Fewer/resolved vulnerabilities in cert vs prod
- **TEST-104**: NO-GO - CRITICAL severity present
- **TEST-105**: NO-GO - HIGH severity present (blocked by threshold)
- **TEST-106**: NO-GO - New vulnerabilities introduced
- **TEST-107**: NO-GO - Severity regression detected
- **TEST-108**: NO-GO - Vulnerable function in use (CRITICAL/HIGH)
- **TEST-109**: GO - Vulnerable function allowed for LOW/MEDIUM

#### Evaluate Mode Tests
- **TEST-201**: GO - No CRITICAL/HIGH vulnerabilities
- **TEST-202**: NO-GO - CRITICAL vulnerabilities present
- **TEST-203**: NO-GO - HIGH vulnerabilities present

### 3. Exclusion Feature Tests
- **TEST-301**: CVE exclusion removes vulnerabilities from assessment
- **TEST-302**: Severity exclusion - vulnerable_function check skipped
- **TEST-303**: Severity exclusion - severity_regression check skipped
- **TEST-304**: Severity exclusion - new_vulnerabilities check skipped
- **TEST-305**: Multiple exclusions combined

### 4. Threshold Tests
- **TEST-401**: max_allowed_severity: CRITICAL (allows HIGH)
- **TEST-402**: max_allowed_severity: HIGH (allows MEDIUM)
- **TEST-403**: max_allowed_severity: MEDIUM (allows LOW)
- **TEST-404**: max_new_vulnerabilities: 0 (no new vulns allowed)
- **TEST-405**: max_new_vulnerabilities: 5 (allows up to 5 new)
- **TEST-406**: max_new_vulnerabilities: -1 (unlimited)
- **TEST-407**: allow_vulnerable_function_for_severities: ['LOW', 'MEDIUM']

### 5. API Integration Tests
- **TEST-501**: Fetch vulnerabilities from certification environment
- **TEST-502**: Fetch vulnerabilities from production environment
- **TEST-503**: Handle empty vulnerability list
- **TEST-504**: Parallel API calls (max_workers)

### 6. Regression Tests
- **TEST-601**: Empty cveIds array handling (42 vulnerabilities case)
- **TEST-602**: Host list mode filtering
- **TEST-603**: CVE comparison with cveIds arrays

## Known Issues to Fix
1. **max_new_vulnerabilities** threshold is not implemented in code
2. Need to validate threshold logic for max_allowed_severity

## Test Execution Strategy
1. Create configuration files for each test scenario
2. Run tests against real environments (integration tests)
3. Document actual vs expected results
4. Fix identified issues
5. Re-run failed tests
