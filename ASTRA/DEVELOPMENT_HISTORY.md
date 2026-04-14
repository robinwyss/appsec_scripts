# ASTRA Development History & Session Memory
**Last Updated**: January 23, 2026  
**Session**: HRP v2.0 Implementation - Supply Chain Focus & Enhanced Topology

---

## 📋 Executive Summary

ASTRA (Application Security Threat & Risk Assessment) is a Python-based risk assessment tool that generates monthly security risk reports for applications monitored by Dynatrace. It supports four risk scoring models: CWRS, REI, HRP v1.0, and HRP v2.0 with advanced supply chain analysis and topology risk assessment.

**Current Status**: ✅ v2.0.0 Complete - HRP v2.0 with 4-Component Risk Model & Supply Chain Focus

---

## 🎯 What Was Built

### Core Functionality
1. **Data Collection** (Parallel)
   - Fetches security problems from Dynatrace API
   - Enriches with detailed vulnerability data
   - Collects process group and host information
   - Uses ThreadPoolExecutor with 10 concurrent workers

2. **Risk Calculation** (Quad Model Support)
   - **CWRS v2.0**: 0-100% scale with Davis Security Score integration (v1.7.0)
   - **REI**: 1-10 logarithmic scale emphasizing severity
   - **HRP v1.0**: 1-10 scale focused on blast radius & supply chain (v1.8.0)
   - **HRP v2.0**: 0-100 scale with power-law dampening & 4-component model ✨ NEW v2.0.0
     - **60%** Vulnerability score with power (0.75) dampening
     - **20%** Supply chain (HIGH IMPORTANCE - standalone component)
     - **15%** Topology (blast radius, connectivity, critical path)
     - **5%** Aging (reduced weight, first-seen timestamp)
   - Entity-level risk scoring for all models

3. **Remediation Priority Analysis** (v1.6.0, Enhanced v1.9.0)
   - **PGI-Focused Layout**: Shows top 5 vulnerabilities for each of the top 3 PGIs ✨ NEW v1.9.0
   - **Davis Score Sorting**: Vulnerabilities ranked by context-aware Davis Security Score ✨ NEW v1.9.0
   - **Adaptive Tables**: Displays 1-3 tables based on number of high-risk PGIs ✨ NEW v1.9.0
   - Entity risk score and vulnerability count per PGI
   - Color-coded severity (CRITICAL/HIGH/MEDIUM/LOW)
   - Davis Score displayed as X.X/10 for easy comparison

4. **CWRS v2.0 Enhancements** ✨ NEW v1.7.0
   - **Davis Security Score**: Uses riskScore field instead of severity levels
   - **Public Exploit Priority**: Properly detects publicExploit with increased weight
   - **Library Vulnerability Ratio**: Calculates vulnerable/total libraries
   - **Network Connectivity Focus**: Replaces management zones with network metrics
   - **Conservative Weights**: Adjusted to emphasize exploitability (30%) over pure vulnerability count

5. **Report Generation**
   - JSON export with complete metadata for temporal comparison
   - Professional PDF reports with model-specific layouts
   - **Remediation Priorities by PGI** (v1.9.0): Top 5 vulnerabilities for top 3 PGIs
   - **CVE-Based Exclusions** (v1.10.0): What-if analysis with vulnerability exclusion stats ✨ NEW
   - Detailed component analysis page
   - Scoring methodology explanation page
   - Exclusion warning on PDF cover page when exclusions applied

6. **What-If Analysis** (Exclusion Mechanism) ✨ NEW v1.10.0
   - **CVE ID Support**: Proper handling of `cveIds` array from Dynatrace API
   - **Multi-Identifier Matching**: Supports CVE, SNYK, Display ID, Security Problem ID
   - **PGI→Parent PG Mapping**: Automatically maps Process Group Instances to parent Process Groups
   - **Statistics Tracking**: Excluded count, affected PGIs, and detailed exclusion log
   - **PDF Warning Banner**: Cover page shows exclusions applied for transparency
   - **Helper Script**: `show_vuln_ids.py` for easy vulnerability ID discovery

---

## 🏗️ Architecture Overview

### File Structure
```
ASTRA/
├── astra_report.py          # Main assessment script (1500+ lines) - NEW v1.5.0
├── astra_phase1.py          # Legacy script (deprecated, use astra_report.py)
├── pdf_generator_beautiful.py  # PDF report generation with exclusion warnings
├── config.yaml              # Active configuration with exclusions support
├── config.example.yaml      # Template configuration
├── requirements.txt         # Python dependencies
├── README.md               # User documentation
├── DESIGN.md               # Technical architecture
├── SUMMARY.md              # Quick reference
├── REFACTORING_NOTES.md    # v1.5.0 refactoring guide
├── DEVELOPMENT_HISTORY.md  # This file - complete session memory
├── quickstart.sh           # Setup automation
├── show_vuln_ids.py        # Helper script for finding vulnerability IDs - NEW v1.10.0
├── test_cve_api.py         # API testing script for CVE data verification - NEW v1.10.0
├── application_risk_indicators.md  # Risk methodology reference
└── reports/                # Generated reports directory
```

### Key Classes

#### 1. **AstraConfig**
- YAML configuration loader
- Dot-notation access (e.g., `config.get('dynatrace.environment')`)
- Handles environment variable interpolation

#### 2. **DataCollector**
- Parallel data fetching with ThreadPoolExecutor
- Method: `_fetch_security_problem_details()` runs in parallel (10 workers)
- Collects: security problems, process groups, hosts
- Defensive coding with isinstance() checks for API inconsistencies

#### 3. **RiskCalculator**
- **Dual model support** via `calculate_overall_risk()`
- Model routing based on `config.assessment.risk_model`
- CWRS: `_calculate_cwrs_risk()` → weighted components
- REI: `_calculate_rei_risk()` → logarithmic scaling

#### 4. **JsonExporter**
- Exports timestamped JSON snapshots
- Includes metadata: report_id, timeframe, risk_model, host_count
- Enables Phase 2 temporal comparison

#### 5. **PdfGenerator**
- reportlab-based PDF generation
- Model-specific layouts and component displays
- **NEW**: `_add_component_analysis_page()` - detailed breakdown
- **NEW**: `_add_methodology_page()` - scoring explanation
- **NEW**: Exclusion warning banner on cover page (v1.10.0)

#### 6. **Exclusion Manager** (v1.10.0) ✨ NEW
- **Method**: `_apply_exclusions(data)` in DataCollector
- **PGI→PG Mapping**: Automatically maps Process Group Instances to parent Process Groups
- **Multi-ID Matching**: CVE IDs, SNYK IDs, Display IDs, Security Problem IDs
- **Stats Tracking**: Returns excluded count, affected PGIs, detailed exclusion list
- **Integration**: Applied after data collection, before risk calculation

---

## 📊 Risk Scoring Models

### Model 1: CWRS v2.0 (Composite Weighted Risk Score)
**Scale**: 0-100%  
**Use Case**: Executive dashboards, conservative risk assessment  
**Version**: 2.0 - Enhanced with Davis Security Score & Network Focus ✨

**Formula**:
```
Risk% = (Vulnerability × 35%) + (Exploitability × 30%) + 
        (Exposure × 20%) + (Criticality × 15%)
```

**Components** (v2.0 Enhancements):

1. **Vulnerability Severity** (35%): **Davis Security Score-based** ✨ NEW
   - Davis Score 9.0-10.0: 10 points each (Critical range)
   - Davis Score 7.0-8.9: 5 points each (High range)
   - Davis Score 4.0-6.9: 2 points each (Medium range)
   - Davis Score 0.1-3.9: 0.5 points each (Low range)
   - Fallback chain: riskScore → baseRiskScore → severity level mapping
   - **Why Davis?** Context-aware scoring considering exploitability, exposure, and reachability

2. **Exploitability** (30%): **Enhanced public exploit detection** ✨ NEW
   - Public exploit available: 10 points (increased from 5) - **highest priority**
   - Vulnerable function in use: 5 points
   - Public network exposure: 3 points
   - Data assets reachable: 3 points
   - **Note**: Weight increased from 25% → 30% to emphasize active threats

3. **Exposure** (20%): **Library vulnerability ratio & network focus** ✨ NEW
   - Vulnerable/Total libraries ratio: 0-10 points (proportional)
   - Network-exposed processes: 1 point per exposed PG (cap 10)
   - Network listener count tracked
   - External service identification (WebService, RemoteService, etc.)
   - **Removed**: Database-centric logic in favor of network connectivity

4. **System Criticality** (15%): **Network connectivity focus** ✨ NEW
   - Network listeners: 0.5 points each (cap 7)
   - External services: 2 points each (cap 6)
   - Host count: 1-2 points based on infrastructure scale
   - **Removed**: Management zone "prod" checks - replaced with attack surface metrics

**Weight Adjustments (Conservative Approach)**:
- Vulnerability: 35% (reduced from 40%) - balances severity with exploitation reality
- Exploitability: 30% (increased from 25%) - emphasizes active threats
- Exposure: 20% (unchanged) - attack surface remains critical
- Criticality: 15% (unchanged) - infrastructure context preserved

**Risk Levels**:
- 0-25%: LOW
- 26-50%: MODERATE
- 51-70%: HIGH
- 71-100%: CRITICAL

### Model 2: REI (Risk Exposure Index)
**Scale**: 1-10 (Logarithmic)  
**Use Case**: Security operations, emphasizing severity

**Formula**:
```python
REI = log₁₀(Total_Risk_Points + 1) × 1.5
```

**Point Accumulation**:

1. **Vulnerability Impact** (Davis Security Score-based)
   - Davis Score 9.0-10.0: 1,000 points
   - Davis Score 7.0-8.9: 500 points
   - Davis Score 4.0-6.9: 100 points
   - Davis Score 0.1-3.9: 10 points
   - Note: Falls back to CVSS baseRiskScore if Davis Score unavailable

2. **Blast Radius Multiplier** (Exponential)
   - Per Process Group: ×1.2
   - Per Host: ×1.5
   - Formula: `1.2^(num_pgs) × 1.5^(num_hosts)`

3. **Threat Intelligence** (Exploitation)
   - Public exploits available: ×2 multiplier
   - CISA KEV listing: ×3 (not yet implemented)
   - Default: ×1 (no active exploits)

4. **Remediation Debt** (Age penalty)
   - Critical vuln age: 10 points/day
   - High vuln age: 5 points/day
   - Unremediated items: +50 base points each

**Risk Levels**:
- 1.0-3.0: LOW (minimal vulnerabilities)
- 3.1-5.0: MODERATE (manageable exposure)
- 5.1-7.0: ELEVATED (notable vulnerabilities)
- 7.1-8.5: HIGH (significant risk)
- 8.6-10.0: CRITICAL (severe, immediate action)

**Why Logarithmic?**
Like the Richter scale, each REI level represents exponentially higher risk. This emphasizes critical vulnerabilities and large blast radius scenarios.

### Model 3: HRP (Holistic Risk Posture)
**Scale**: 1-10  
**Use Case**: Management reporting, blast radius & supply chain focus  
**Version**: 1.0 - Initial implementation ✨ NEW v1.8.0

**Formula**:
```
Total Score (0-100) = (Critical Vulns × 50%) + (Topology Risk × 25%) + (Aging × 25%)
HRP = (Total Score / 100) × 9 + 1
```

**Components**:

1. **Critical Vulnerabilities** (50%): **Davis Security Score-weighted** (0-100 points)
   - Davis Score 9.0-10.0: 15 points each
   - Davis Score 7.0-8.9: 8 points each
   - Davis Score 4.0-6.9: 3 points each
   - Davis Score 0.1-3.9: 1 point each
   - **Focus**: Emphasizes high-severity issues over count

2. **Topology Risk / Supply Chain** (25%): **Blast radius analysis** (0-100 points)
   - Affected entities (blast radius): 10-40 points based on count
   - Vulnerable library ratio: (vulnerable libs / total libs) × 60 points
   - **Focus**: Interconnected risk and software component health

3. **Aging Factor / Remediation Velocity** (25%): **Security debt** (0-100 points)
   - Critical: 10pts if >90 days old, 5pts if >30 days, 2pts if >7 days
   - High: 8pts if >180 days, 4pts if >90 days, 2pts if >30 days
   - Medium: 4pts if >365 days, 2pts if >180 days
   - **Focus**: Penalties for long-standing vulnerabilities

**Risk Levels**:
- 1.0-3.9: LOW (well-maintained, limited blast radius)
- 4.0-6.4: MODERATE (manageable security debt)
- 6.5-8.4: HIGH (significant interconnected risk)
- 8.5-10.0: CRITICAL (severe supply chain exposure)

**Key Differentiators from REI**:
- **Supply chain focus**: Library vulnerability ratios matter more than total counts
- **Blast radius emphasis**: Affected entity count heavily weighted
- **Remediation velocity**: Time-based penalties highlight security debt
- **Management perspective**: Answers "How interconnected is our risk?" vs REI's "How severe?"

---

## 🔧 Implementation Details

### Parallel Processing
```python
# ThreadPoolExecutor with 10 workers
max_workers = self.config.get('assessment.max_workers', 10)
with ThreadPoolExecutor(max_workers=max_workers) as executor:
    futures = [executor.submit(self._fetch_security_problem_details, sp) 
               for sp in security_problems]
```

### Model Selection
```python
# In RiskCalculator.calculate_overall_risk()
risk_model = self.config.get('assessment.risk_model', 'CWRS')
if risk_model == 'REI':
    return self._calculate_rei_risk(data)
elif risk_model == 'HRP':
    return self._calculate_hrp_risk(data)
else:
    return self._calculate_cwrs_risk(data)
```

### REI Logarithmic Calculation
```python
import math
total_points = (vuln_impact * blast_radius * threat_mult) + debt_points
rei_score = math.log10(total_points + 1) * 1.5
rei_score = min(rei_score, 10.0)  # Cap at 10
```

### Defensive API Handling
```python
# Handle Dynatrace API inconsistencies
if isinstance(sp.get('riskAssessment'), dict):
    risk_level = sp['riskAssessment'].get('riskLevel', 'LOW')
else:
    risk_level = 'LOW'  # Default if API returns string
```

---

## 📈 Sample Run Results

### CWRS Model
- **Score**: 52/100 (HIGH)
- **Data**: 188 security problems, 219 process groups, 6 hosts
- **Breakdown**:
  - Vulnerability Severity: ~20/40
  - Exploitability: ~13/25
  - Exposure: ~12/20
  - Criticality: ~7/15

### REI Model
- **Score**: 9.96/10 (CRITICAL)
- **Data**: Same 188 security problems, **28 entities mapped**
- **Breakdown**:
  - Vulnerability Impact: 42,920 points
  - Blast Radius: 100.0× multiplier
  - Threat Intelligence: 1.0× (no active exploits)
  - Remediation Debt: 79,232 points
  - **Total Risk Points**: 4,371,232
  - **REI Calculation**: log₁₀(4,371,232 + 1) × 1.5 = 9.96

**Key Insight**: REI's logarithmic approach gives a more urgent signal (9.96 CRITICAL) compared to CWRS (52 HIGH) for the same dataset, emphasizing the exponential nature of risk when vulnerabilities accumulate.

---

## 🐛 Known Issues & Fixes Applied

### Issue 1: Entity-Level Mapping
**Problem**: 0 entities with vulnerabilities despite 188 security problems  
**Root Cause**: Mismatch between `remediationItems` (PROCESS_GROUP IDs) and collected entity data (PROCESS_GROUP_INSTANCE IDs)  
**Fix Applied**: Switched from `remediationItems` matching to `relatedEntities` structure traversal
- Changed `calculate_entity_risk()` to iterate through `relatedEntities.services`, `hosts`, `kubernetesWorkloads`, `kubernetesClusters`
- Match entity IDs against `affectedEntities` arrays within each related entity
- **Result**: Successfully mapped 28 entities with vulnerabilities (verified Jan 22, 2026)

**Technical Details**:
```python
# OLD (incorrect): Used remediationItems with PROCESS_GROUP IDs
entity_vulns = [v for v in vulnerabilities if any(
    item.get('id') == entity_id for item in v.get('remediationItems', [])
)]

# NEW (correct): Use relatedEntities with PROCESS_GROUP_INSTANCE IDs
for entity_type in ['services', 'hosts', 'kubernetesWorkloads', 'kubernetesClusters']:
    entities_list = related_entities.get(entity_type, [])
    for related_entity in entities_list:
        affected = related_entity.get('affectedEntities', [])
        if entity_id in affected:
            entity_vulns.append(v)
```

### Issue 2: Risk Model Metadata Bug
**Problem**: JSON metadata always showed `risk_model: "CWRS"` regardless of config  
**Cause**: Hardcoded string in JsonExporter.export() method  
**Fix Applied**: Changed line 662 to dynamically read from config
```python
# OLD: 'risk_model': 'CWRS'
# NEW: 'risk_model': self.config.get('assessment.risk_model', 'CWRS')
```
**Status**: ✅ Fixed (verified Jan 22, 2026)

### Issue 3: Indentation Errors
**Problem**: Mixed indentation in early implementations  
**Fix**: Applied consistent 4-space indentation throughout  
**Status**: ✅ Fixed

### Issue 3: Import Errors
**Problem**: reportlab `colors` module not available in method scope  
**Fix**: Moved imports to top-level with try/except graceful degradation  
**Status**: ✅ Fixed

### Issue 4: Type Checking
**Problem**: `AttributeError: 'str' object has no attribute 'get'`  
**Cause**: Dynatrace API sometimes returns strings instead of dicts  
**Fix**: Added defensive `isinstance()` checks before accessing nested fields  
**Status**: ✅ Fixed

### Issue 5: PDF Method References
**Problem**: `NameError: name 'Paragraph' is not defined` in new helper methods  
**Fix**: Made reportlab classes available as instance variables:
```python
self.Paragraph = Paragraph
self.Spacer = Spacer
self.Table = Table
# etc.
```
**Status**: ✅ Fixed

### Issue 6: Entity Risk Score Display Scale
**Problem**: REI model entity scores displayed as "/100" instead of "/10" in PDF reports  
**Root Cause**: Hardcoded scale in entity risk display (line ~884)  
**Fix Applied**: Added dynamic scale detection based on risk model:
```python
risk_model = data['overall_risk'].get('model', 'CWRS')
scale_max = "10" if risk_model == 'REI' else "100"
story.append(Paragraph(
    f"Risk Score: <b>{entity['risk_score']}/{scale_max}</b> ({entity['risk_rating']})",
    styles['Normal']
))
```
**Status**: ✅ Fixed (v1.5.0)

### Issue 7: Using CVSS Instead of Davis Security Score
**Problem**: Script was using `baseScore` (which doesn't exist in API) instead of Davis Security Score  
**Root Cause**: Misunderstanding of Dynatrace API response structure
- API returns `riskScore` (Davis Security Score) - contextual, preferred
- API returns `baseRiskScore` (CVSS) - base severity only
- Code was looking for non-existent `baseScore` field

**Fix Applied**: Updated `_calculate_rei_vuln_impact()` to use Davis Security Score:
```python
# Proper fallback chain
davis_score = risk_assessment.get('riskScore', 
              risk_assessment.get('baseRiskScore', 5.0))
```
**Status**: ✅ Fixed (v1.5.0)

### Issue 8: CVE-Based Exclusions Not Working
**Problem**: Exclusions configured but not applied - 0 vulnerabilities excluded despite config  
**Root Causes** (3 separate issues):
1. **CVE Field Mismatch**: Code looked for `cveId` (singular) but API returns `cveIds` (plural array)
2. **PGI vs PG Mismatch**: Exclusions specified `PROCESS_GROUP_INSTANCE-xxx` but remediationItems contain `PROCESS_GROUP-xxx` (parent IDs)
3. **Limited ID Support**: Only checked for CVE IDs, ignored SNYK IDs, Display IDs, Security Problem IDs

**Fix Applied** (v1.10.0):
```python
# 1. Handle cveIds as array
cve_ids = problem.get('cveIds', [])
if isinstance(cve_ids, list):
    vuln_identifiers.update(cve_ids)

# 2. Build PGI→PG mapping
pgi_to_pg_map = {}
for pg in data.get('process_groups', []):
    pgi_id = pg.get('entityId')
    if 'fromRelationships' in pg and 'isInstanceOf' in pg['fromRelationships']:
        for parent in pg['fromRelationships']['isInstanceOf']:
            parent_pg_id = parent.get('id')
            if parent_pg_id:
                pgi_to_pg_map[pgi_id] = parent_pg_id

# 3. Support multiple identifier types
vuln_identifiers = set()
vuln_identifiers.update(problem.get('cveIds', []))
vuln_identifiers.add(problem.get('externalVulnerabilityId'))
vuln_identifiers.add(problem.get('displayId'))
vuln_identifiers.add(problem.get('securityProblemId'))
```

**Verification**:
- Before: 70 vulnerabilities, 0 excluded
- After: 69 vulnerabilities, 1 excluded (CVE-2023-44487) ✅
- Test case: HTTP/2 Rapid Reset Attack successfully removed from reports

**Status**: ✅ Fixed (v1.10.0 - Jan 23, 2026)

### Issue 9: CVE IDs Not Displayed in Helper Script
**Problem**: Helper script showed "N/A" for CVE IDs despite API having them  
**Root Cause**: JSON export didn't include `cveIds` field in remediation_priorities  
**Fix Applied**: Updated remediation priority calculation to include `cveIds` array
**Status**: ✅ Fixed (v1.10.0)
```python
# Get Davis Security Score (riskScore) - preferred over CVSS baseRiskScore
davis_score = risk_assessment.get('riskScore', 0)

# If no Davis score, fall back to baseRiskScore (CVSS), then severity level
if davis_score == 0:
    davis_score = risk_assessment.get('baseRiskScore', 0)
```

**Why Davis Security Score is Better**:
- Considers base CVSS score
- Factors in network exposure (public vs internal)
- Includes data assets at risk
- Accounts for known exploits
- Evaluates vulnerable function usage
- More context-aware than raw CVSS

**Status**: ✅ Fixed (v1.5.0)

### Issue 8: PDF Metric Card Visual Overlap
**Problem**: Numbers overlapping text labels in executive summary metric cards  
**Root Cause**: Insufficient row height allocation in table layout  
**Fix Applied**: Added explicit rowHeights and changed vertical alignment:
```python
# Added rowHeights parameter with proper spacing
rowHeights=[1.8*cm, 0.8*cm]
# Changed VALIGN: title BOTTOM, value TOP for proper separation
```
**Status**: ✅ Fixed (v1.6.0)

### Issue 9: Remediation Impact Values All 0.01
**Problem**: All remediation priorities showing impact of 0.01-0.02  
**Root Cause**: Not a bug - mathematically correct behavior at REI 9.96/10  
**Explanation**: 
- REI uses logarithmic scale: log₁₀(4,371,232 risk points) × 1.5 = 9.96
- Removing 50,000 points: log₁₀(4,321,232) × 1.5 = 9.95
- Impact: 0.01 is correct at this scale
- At CRITICAL levels with 188 vulnerabilities, individual remediation has minimal impact
- **Resolution**: Working as designed - comprehensive remediation needed, not single-vulnerability fixes
**Status**: ✅ Validated (v1.6.0) - Not a bug

### Issue 10: CWRS Using Severity Levels Instead of Davis Security Score
**Problem**: CWRS v1.0 was using simple severity levels (CRITICAL/HIGH/MEDIUM/LOW) instead of the more accurate Davis Security Score  
**Root Cause**: Initial implementation designed before understanding Davis Security Score benefits  
**Fix Applied** (v1.7.0): Enhanced `_calculate_vulnerability_severity_score()` to use Davis Security Score with fallback chain  
**Status**: ✅ Fixed (v1.7.0)

---

## 📝 Configuration Reference

### Key Settings

```yaml
# Dynatrace Connection
dynatrace:
  environment: "https://your-tenant.live.dynatrace.com"
  api_token: "${DT_API_TOKEN}"  # Use env var for security
  verify_ssl: true

# Assessment Options
assessment:
  timeframe: "now-30d"  # 30-day lookback
  risk_model: "REI"     # Options: "CWRS" or "REI"
  max_workers: 10       # Parallel processing threads

# Filters
filters:
  type: "process_group"
  ids: ["PROCESS_GROUP-xxxxx"]  # Specific PGs, or empty for all
  management_zones: []
  tags: []

# Output
output:
  json_path: "./reports"
  pdf_path: "./reports"
```

---

## 🎨 Enhanced PDF Features

### Page 1: Executive Summary
- Overall risk score (model-specific display)
- Risk rating with color coding
- Component breakdown table
- Summary statistics
- Vulnerability count by severity

### Page 2: Detailed Component Analysis
**CWRS Mode**:
- Vulnerability severity table with point values
- Exploitability breakdown (public exposure)
- Exposure metrics (attack surface)
- System criticality factors

**REI Mode**:
- Vulnerability impact points table (CVSS mapping)
- Blast radius calculation explanation
- Threat intelligence multiplier details
- Remediation debt breakdown with aging formula

### Page 3: Vulnerability Distribution
- Severity breakdown chart
- Total counts by severity level
- Recommended actions based on severity mix

### Page 4: Top Remediation Priorities by PGI ✨ Enhanced v1.9.0
- **PGI-Focused Layout**: Up to 3 tables (one per top-risk PGI)
- **Top 5 Vulnerabilities**: Per PGI, sorted by Davis Security Score (descending)
- **Entity Context**: PGI name, risk score (X.XX/10), vulnerability count
- **Davis Score Column**: Context-aware risk score (0-10 scale) instead of impact
- **Color-Coded Severity**: CRITICAL/HIGH/MEDIUM/LOW with color indicators
- **CVE ID**: Displayed prominently with truncated vulnerability title
- **Adaptive Display**: Shows 1 table if 1 PGI, 2 tables if 2 PGIs, 3 tables if 3+ PGIs
- **Explanatory Note**: Davis Score methodology and context-aware factors

### Page 5: Risk Analysis Breakdown
- Component scores and calculations
- Model-specific risk factor details
- Entity risk distribution

### Page 6: High-Risk Entities
- Top 10 highest-risk entities
- Entity-specific risk scores
- Vulnerability counts per entity

### Page 7: Scoring Methodology
**CWRS Mode**:
- Formula explanation with component weights
- Risk level interpretation table
- Threshold management guidance
- Component weight rationale
- Action recommendations based on score

**REI Mode**:
- Logarithmic scale explanation (like Richter)
- Calculation formula with example
- Risk level interpretation (1-10 scale)
- Trend monitoring guidance
- Key risk amplifiers list
- Context-aware action recommendations

**Dynamic Recommendations** (both modes):
- 🔴 CRITICAL: Urgent executive notification, emergency plan
- 🟠 HIGH: 7-day remediation schedule, increased monitoring
- 🟡 MODERATE: 30-day planning, policy review
- 🟢 LOW: Maintain posture, routine monitoring

---

## 🚀 Usage

### Basic Run (Phase 1)
```bash
cd ASTRA
python3 astra_report.py -c config.yaml
# or explicitly:
python3 astra_report.py -c config.yaml --phase-1
python3 astra_report.py -c config.yaml -1
```

### Phase 2 (Future - Temporal Comparison)
```bash
python3 astra_report.py -c config.yaml --phase-2
python3 astra_report.py -c config.yaml -2 --baseline reports/astra_report_20260122.json
```

### With Debug Logging
```bash
python3 astra_report.py -c config.yaml --debug
```

### Switching Risk Models
Edit `config.yaml`:
```yaml
assessment:
  risk_model: "CWRS"  # or "REI"
```

### Output
- JSON: `reports/astra_report_YYYYMMDD_HHMMSS.json`
- PDF: `reports/astra_YYYYMMDD_HHMMSS.pdf`
- Log: `astra_report.log` (was `astra_phase1.log` in v1.4.0)

---

## 🔮 Future Enhancements (Phase 2+)

### Immediate Roadmap
1. **CISA KEV Integration**
   - Add CVE lookup against Known Exploited Vulnerabilities catalog
   - Implement ×3 multiplier in REI model for KEV-listed CVEs

2. **Phase 2: Temporal Comparison**
   - Load previous JSON snapshots
   - Calculate risk improvement delta
   - Identify resolved/new vulnerabilities
   - Generate trend graphs

3. **PARM Model** (Probabilistic Application Risk Model)
   - 0-100% probability of security incident in next 30 days
   - Vulnerability exploit probability calculation
   - Technology stack risk assessment
   - Attack history factor integration

### Long-term Ideas
- Grail integration for historical trending
- DQL queries for time-series analysis
- Automated alerting when risk increases >10% in 7 days
- Risk velocity tracking (Δ%/Δt)
- Multi-environment comparison
- SLA breach prediction
- Custom risk thresholds per management zone

---

## 🔑 Key Learnings

### Technical Decisions
1. **Parallel Processing**: Critical for performance with 188+ vulnerabilities
2. **Dual Model Support**: Different stakeholders need different views
3. **Defensive Coding**: Dynatrace API returns inconsistent data types
4. **Logarithmic Scaling**: Better emphasizes critical risks than linear
5. **Enhanced Documentation**: PDF reports are communication tools, not just data dumps

### Best Practices Applied
- Environment variables for API tokens
- YAML configuration for flexibility
- JSON snapshots for reproducibility
- Comprehensive error handling
- Professional PDF formatting with reportlab
- Clear separation of concerns (data/calc/export)

### Gotchas
- reportlab classes need explicit instance variable assignment for helper methods
- Dynatrace API sometimes returns strings when dicts expected
- Entity mapping between security problems and process groups isn't 1:1
- sed -i requires backup extension on macOS (used .bak, .bak2, .bak3)

---

## 📚 Dependencies

```
reportlab>=3.6.0    # PDF generation
PyYAML>=6.0         # Configuration parsing
requests>=2.28.0    # HTTP client (via dynatrace_api.py)
pandas>=1.5.0       # Data handling
```

---

## 🤝 Integration Points

### Existing Codebase
- Uses `dynatrace_api.py` from parent directory
- Follows same patterns as `export_vulnerabilities.py`
- Compatible with existing Dynatrace tenant configuration

### Dynatrace API Endpoints Used
```
/api/v2/securityProblems
/api/v2/securityProblems/{id}?fields=+relatedEntities,+riskAssessment,+managementZones
/api/v2/securityProblems/{id}/remediationItems
/api/v2/entities (process groups and hosts)
```

---

## 💡 Quick Reference Commands

```bash
# Setup
cd ASTRA
pip install -r requirements.txt

# Configure
cp config.example.yaml config.yaml
# Edit config.yaml with your settings

# Run Phase 1 (default)
python3 astra_report.py -c config.yaml

# Run Phase 1 explicitly
python3 astra_report.py -c config.yaml -1

# Run Phase 2 (when implemented)
python3 astra_report.py -c config.yaml -2

# Run CWRS model
sed -i '' 's/risk_model: "REI"/risk_model: "CWRS"/' config.yaml
python3 astra_report.py -c config.yaml

# Run REI model
sed -i '' 's/risk_model: "CWRS"/risk_model: "REI"/' config.yaml
python3 astra_report.py -c config.yaml

# Debug mode
python3 astra_report.py -c config.yaml --debug

# View reports
open reports/astra_*.pdf
cat reports/astra_report_*.json | jq .overall_risk

# Compare models
python3 astra_report.py -c config.yaml  # REI
sed -i '' 's/REI/CWRS/' config.yaml && python3 astra_report.py -c config.yaml
# Compare the two PDFs
```

---

## 📊 Performance Metrics

- **API Calls**: ~200-400 (depends on security problem count)
- **Parallel Workers**: 10 concurrent
- **Typical Runtime**: 15-30 seconds for 188 vulnerabilities
- **Report Generation**: <1 second (PDF + JSON)
- **Memory Usage**: Minimal (<100MB)

---

## 🎯 Success Criteria Met

✅ Triple risk model implementation (CWRS + REI + HRP) ✨ **v1.8.0**  
✅ Parallel data collection (10 workers)  
✅ JSON export for temporal comparison  
✅ Professional PDF reports  
✅ Model-specific layouts for all three models ✨ **v1.8.0**  
✅ Detailed component analysis page  
✅ Scoring methodology explanation page  
✅ Dynamic recommendations  
✅ Comprehensive documentation  
✅ Successful test runs with real data (all 3 models) ✨ **v1.8.0**  
✅ Bug-free execution on macOS  
✅ Entity mapping fully functional (28 entities tracked)  
✅ Risk model metadata dynamically set from config  
✅ Davis Security Score integration (context-aware vulnerability assessment)  
✅ Multi-phase architecture (extensible for Phase 2)  
✅ Modular, portable code structure  
✅ Correct entity score display for all models (/10 for REI & HRP, /100 for CWRS) ✨ **v1.8.0**  
✅ Phase selection via command-line flags  
✅ **PGI-Focused Remediation Priorities** (v1.9.0): Top 5 vulns per top 3 PGIs ✨ **NEW**  
✅ **Davis Score-Based Prioritization** (v1.9.0): Context-aware risk ranking ✨ **NEW**  
✅ **Adaptive Table Layout** (v1.9.0): 1-3 tables based on entity count ✨ **NEW**  
✅ **CVE-Based Exclusion Mechanism** (v1.10.0): What-if analysis with stats ✨ **NEW**  
✅ **Multi-Identifier Matching** (v1.10.0): CVE, SNYK, Display ID, Problem ID support ✨ **NEW**  
✅ **PGI→Parent PG Mapping** (v1.10.0): Automatic exclusion filtering ✨ **NEW**  
✅ **Exclusion Transparency** (v1.10.0): PDF cover page warning banner ✨ **NEW**  
✅ **Helper Tools** (v1.10.0): show_vuln_ids.py, test_cve_api.py ✨ **NEW**  
✅ **HRP blast radius & supply chain analysis** ✨ **v1.8.0**  
✅ **Vulnerable/total library ratio calculation** ✨ **v1.8.0**  
✅ **Remediation velocity & aging factor tracking** ✨ **v1.8.0**  
✅ **Three distinct risk perspectives for different stakeholders** ✨ **v1.8.0**  

---

## 📞 Contact Context

**Developer**: Mattia Rambelli (Dynatrace)  
**Tenant**: jak10854.live.dynatrace.com  
**Date Started**: January 22, 2026  
**Latest Update**: January 23, 2026 (v1.10.0)  
**Session Type**: Copilot-assisted development

---

## 🔍 Troubleshooting Guide

### Problem: Import errors
**Solution**: Check Python path includes parent directory
```bash
export PYTHONPATH="${PYTHONPATH}:$(pwd)/.."
```

### Problem: 401 Authentication error
**Solution**: Verify API token has correct permissions:
- securityProblems.read
- entities.read

### Problem: 0 entities with vulnerabilities
**Solution**: This is now FIXED (v1.4.0). The tool correctly maps entities by checking `relatedEntities` structure instead of `remediationItems`. Should now see proper entity counts (e.g., 28 entities).

### Problem: PDF not generating
**Solution**: Install reportlab:
```bash
pip install reportlab
```6.0** (Jan 22, 2026): Top 10 Remediation Priorities by Impact
  - Added `calculate_remediation_priorities()` method to RiskCalculator
  - Calculates what-if scenarios: score impact if each vulnerability is remediated
  - Identifies top 10 vulnerabilities by descending impact value
  - Includes affected PGIs with entity names
  - Added new PDF page after Vulnerability Distribution
  - Updated JSON export to include `remediation_priorities` array
  - Color-coded severity display in priorities table
  - Shows impact as score reduction (e.g., -0.52/10 for REI, -15.3/100 for CWRS)
- **v1.

### Problem: JSON but no PDF
**Solution**: Check logs for reportlab import errors. JSON export always works.

### Problem: Exclusions not working (0 vulnerabilities excluded)
**Solution** (v1.10.0+): Three possible causes:
1. **Wrong PGI ID**: Use `python show_vuln_ids.py` to list all PGIs and their IDs
2. **Wrong vulnerability ID**: Run `python show_vuln_ids.py <PGI_ID>` to see exact IDs (CVE, SNYK, etc.)
3. **Config syntax error**: Ensure proper YAML formatting under `exclusions.pgis`

Example working config:
```yaml
exclusions:
  pgis:
    - pgi_id: "PROCESS_GROUP_INSTANCE-E45DB9E6F534EEF6"
      vulnerability_ids:
        - "CVE-2023-44487"
        - "SNYK-JAVA-ORGAPACHETOMCAT-5953330"
```

Run with `--debug` flag to see exclusion matching details in logs.

### Problem: CVE IDs showing as N/A
**Solution**: This is expected for some vulnerabilities. Not all vulnerabilities have official CVE IDs. Use alternative IDs:
- **SNYK IDs** (externalVulnerabilityId): Most common for third-party libraries
- **Display IDs** (e.g., S-309): Always available
- **Security Problem IDs**: Numeric Dynatrace internal IDs

The exclusion mechanism supports all identifier types.

---

## 🎓 Learning Resources

- **CWRS Model**: See `application_risk_indicators.md` Solution 1
- **REI Model**: See `application_risk_indicators.md` Solution 2
- **PARM Model**: See `application_risk_indicators.md` Solution 3 (future)
- **Dynatrace API**: https://www.dynatrace.com/support/help/dynatrace-api
- **reportlab Docs**: https://www.reportlab.com/docs/reportlab-userguide.pdf

## 📅 Version History

- **v1.10.0** (Jan 23, 2026): CVE-Based Exclusion Mechanism for What-If Analysis
  - **CVE Field Fix**: Changed from `cveId` (singular) to `cveIds` (array) to match Dynatrace API structure
  - **PGI→PG Mapping**: Implemented automatic mapping from Process Group Instances to parent Process Groups for exclusion matching
  - **Multi-Identifier Support**: Exclusions now match against CVE IDs, SNYK IDs (externalVulnerabilityId), Display IDs, and Security Problem IDs
  - **Helper Script**: Created `show_vuln_ids.py` to easily discover vulnerability identifiers for any PGI
  - **Enhanced JSON Export**: Added `cveIds` array to remediation_priorities for better tracking
  - **PDF Warning Banner**: Exclusion warning displayed on cover page when exclusions are applied
  - **Statistics Tracking**: Detailed exclusion stats (count, affected PGIs, vulnerability list) in JSON and logs
  - **Test Verification**: Successfully tested with CVE-2023-44487 exclusion (70→69 vulnerabilities)
  - **Config Documentation**: Updated config.yaml with comprehensive examples and CVE ID prominence
  - **API Verification**: Created test_cve_api.py to verify CVE data structure from Dynatrace API
  - Modified `_apply_exclusions()` in astra_report.py (lines 172-250)
  - Enhanced exclusion matching logic with PGI-to-parent-PG relationship traversal
  - Root cause analysis from production_promotion_check.py showing proper CVE handling
- **v1.9.0** (Jan 23, 2026): Enhanced Remediation Priorities with Davis Score & PGI Focus
  - **PGI-Focused Tables**: Changed from single top-10 table to up to 3 tables (one per top PGI)
  - **Davis Security Score**: Replaced Impact column (which showed 0.0) with Davis Score (0-10 scale)
  - **Top 5 per PGI**: Each table shows 5 highest-risk vulnerabilities for that Process Group Instance
  - **Adaptive Layout**: Automatically displays 1-3 tables based on available high-risk entities
  - **Enhanced Readability**: Includes entity name, risk score, and vulnerability count headers
  - **Sorting Logic**: Vulnerabilities sorted by Davis Security Score (riskScore field) descending
  - **Context-Aware**: Davis Score considers attack detectability, exploit complexity, environmental factors
  - **PDF Improvements**: Cleaner table layout with 4 columns (#, Vulnerability, Severity, Davis Score)
  - **Better Prioritization**: Focus on highest-risk PGIs first, then their most critical vulnerabilities
  - Modified `_add_remediation_priorities()` in pdf_generator_beautiful.py
  - Rationale: Impact calculation was returning 0.0 values; Davis Score provides immediate actionable data
- **v1.8.0** (Jan 22, 2026): HRP Model - Holistic Risk Posture with Blast Radius & Supply Chain
  - **New Risk Model**: Added HRP (Holistic Risk Posture) as third assessment option
  - **Component Calculation**: Critical Vulnerabilities (50%), Topology Risk (25%), Aging Factor (25%)
  - **Blast Radius Analysis**: Tracks affected entities and calculates vulnerable/total library ratio
  - **Supply Chain Focus**: Emphasizes software component inventory health and dependencies
  - **Remediation Velocity**: Time-weighted penalties for aging vulnerabilities (CRITICAL: 10pts/day >90d)
  - **1-10 Scale**: Linear conversion from 0-100 weighted score: (score/100)×9+1
  - **PDF Integration**: Added HRP breakdown page, interpretation text, and scale detection
  - **Config Support**: Added "HRP" option to risk_model configuration
  - **Entity-Level HRP**: Full entity risk calculation support
  - Based on risk_indicators_g.md "The Holistic Risk Posture" methodology
  - Uses API data only (no Grail dependency)
  - Compatible with existing remediation priorities feature
- **v1.7.0** (Jan 22, 2026): CWRS v2.0 - Conservative Risk Assessment with Davis Security Score
  - **Davis Security Score Integration**: Enhanced `_calculate_vulnerability_severity_score()` to use riskScore field with fallback chain (riskScore → baseRiskScore → severity mapping)
  - **Public Exploit Priority**: Updated `_calculate_exploitability_score()` with proper publicExploit detection, increased weight from 5→10 points
  - **Library Vulnerability Ratio**: Modified `_calculate_exposure_score()` to calculate vulnerable/total library ratio instead of simple counts
  - **Network Connectivity Focus**: Refactored `_calculate_criticality_score()` to use network listeners and external services instead of management zone checks
  - **Conservative Weight Adjustment**: Changed weights to Vulnerability 35% (down from 40%), Exploitability 30% (up from 25%), Exposure 20%, Criticality 15%
  - **Rationale**: Emphasizes exploitability and active threats over pure vulnerability counts, errs on side of caution
  - Added dataAssetsReachable indicator to exploitability scoring
  - Removed database-centric logic in favor of network exposure metrics
- **v1.6.0** (Jan 22, 2026): Top 10 Remediation Priorities by Impact
  - Added `calculate_remediation_priorities()` method to RiskCalculator
  - Calculates what-if scenarios: score impact if each vulnerability is remediated
  - Identifies top 10 vulnerabilities by descending impact value
  - Includes affected PGIs with entity names
  - Added new PDF page after Vulnerability Distribution
  - Updated JSON export to include `remediation_priorities` array
  - Color-coded severity display in priorities table
  - Shows impact as score reduction (e.g., -0.52/10 for REI, -15.3/100 for CWRS)
  - Fixed PDF metric card visual overlap issue with rowHeights and VALIGN adjustments
  - Fixed color constant names (MODERATE not MEDIUM, DIVIDER not TABLE_BORDER)
  - Implemented deep copy strategy for accurate recalculation
  - Added progress logging for priority calculation
- **v1.5.0** (Jan 22, 2026): Multi-phase architecture refactoring
  - Renamed script to `astra_report.py` for multi-phase support
  - Added phase selection flags: `-1` (Phase 1), `-2` (Phase 2 placeholder)
  - Modularized code: `run_phase1()`, `run_phase2()` functions
  - Fixed entity score display scale (REI: /10, CWRS: /100)
  - Switched from CVSS to Davis Security Score for better context-awareness
  - Updated all documentation and examples
  - Created REFACTORING_NOTES.md for future development
- **v1.4.0** (Jan 22, 2026): Fixed entity mapping bug (0→28 entities) & risk_model metadata bug
- **v1.3.0** (Jan 22, 2026): Enhanced PDF with analysis + methodology pages
- **v1.2.0** (Jan 22, 2026): Added REI model support
- **v1.1.0** (Jan 22, 2026): Added parallelization (10 workers)
- **v1.0.0** (Jan 22, 2026): Initial CWRS v1.0 implementation

---

## 🔬 Risk Model Comparison & Use Cases

### When to Use Each Model

| Model | Scale | Best For | Key Strength | Update Frequency |
|-------|-------|----------|--------------|------------------|
| **CWRS** | 0-100% | Executive dashboards, compliance reporting | Balanced, easy to understand | Monthly |
| **REI** | 1-10 | Security operations, incident response | Emphasizes severity & active threats | Weekly |
| **HRP v1** | 1-10 | Management, CISO reporting | Supply chain & blast radius focus | Monthly |
| **HRP v2** | 0-100 | Remediation tracking, sensitivity analysis | Supply chain priority, visible risk reduction | Bi-weekly |

### Real-World Example (188 vulnerabilities, 7 hosts, 227 PGs)

**Same Dataset, Four Perspectives:**

1. **CWRS v2.0**: 52/100 (HIGH)
   - Conservative weighted assessment
   - Balanced across 4 components
   - Good for quarterly board presentations

2. **REI**: 9.96/10 (CRITICAL)
   - Logarithmic scale emphasizes urgency
   - Total risk points: 4,371,290
   - Excellent for SOC prioritization

3. **HRP v1.0**: 8.65/10 (CRITICAL)
   - Blast radius & supply chain focused
   - Critical vulns: 100/100, Topology: 40/100, Aging: 100/100
   - Perfect for addressing security debt

4. **HRP v2.0**: 90.5/100 (CRITICAL) ✨ NEW
   - Power-law dampening with enhanced sensitivity
   - Vulnerabilities: 100/100, **Supply Chain: 100/100**, Topology: 40/100, Aging: 100/100
   - Remediating 10 vulnerabilities = 5-8 point reduction (visible impact)
   - Excellent for tracking remediation progress

### Key Insight
The four models provide **complementary perspectives**:
- **CWRS** answers: "What's our overall posture?"
- **REI** answers: "How severe is the immediate threat?"
- **HRP v1.0** answers: "How interconnected and aged is our risk?"
- **HRP v2.0** answers: "How much will remediation improve our score?" ✨ NEW

Use all four for comprehensive risk assessment, or select the model that best matches your stakeholder audience.

---

## 🆕 Version 2.0.0 - HRP v2.0 Implementation (December 2024)

### Major Features Added

#### 1. **HRP v2.0 Risk Model** (Complete Redesign)
**Problem Solved**: HRP v1.0 had poor sensitivity - excluding 11 vulnerabilities showed zero score change (8.65→8.65)

**What HRP v2.0 Measures**: **"Potential Business Impact from Security Exposure"**

HRP v2.0 quantifies the potential operational and security damage if an attacker successfully exploited the identified vulnerabilities, weighted by:
- Exploitability likelihood (public exploits, CVE IDs, severity)
- Attack surface breadth (vulnerable library ratio)
- System criticality (blast radius, interconnectivity, critical paths)
- Exposure duration (time unpatched)

**Solution**: New 0-100 scale model with:
- **Power-law dampening** (exponent 0.75) instead of threshold-based scoring
- **4-component structure** with supply chain as standalone high-priority component (20%)
- **Enhanced sensitivity**: 10 vulnerabilities = 5-8 point reduction
- **Adaptive hybrid dampening** for extreme vulnerability counts (500+)

**Mathematical Foundation**:
```
Overall Score = 0.60 × S_vuln + 0.20 × S_supply + 0.15 × S_topo + 0.05 × S_aging

S_vuln = 100 × (Σ_weighted^0.75) / (300^0.75)
S_supply = 100 × (vuln_ratio^0.7)
S_topo = 0.40×blast + 0.35×connectivity + 0.25×critical_path
S_aging = Σ [(days/365) × severity_weight × 0.7]
```

**Key Parameters** (config.yaml):
- `dampening_function: "power"` with `dampening_exponent: 0.75`
- `max_theoretical_score: 300` for normalization
- `exploitability_multiplier: 3.0` for public exploits
- `cve_multiplier: 2.2` for CVE-identified vulnerabilities

#### 2. **Supply Chain as Standalone Component** (20% Weight)
**Why This Matters**: Supply chain vulnerabilities are a top security concern

**Implementation**:
- Extracts vulnerable libraries from `packageName` and `technology` fields
- Calculates vulnerable/total library ratio with power-law scaling
- **HIGH IMPORTANCE label** in PDF reports
- Separate from topology (previously combined in v1.0)

**Data Source Fix**:
- Original: Used `vulnerableComponents` field (was null in API)
- Fixed: Uses `packageName` + `technology` from vulnerability data
- Now properly tracks vulnerable packages: `{technology}_{packageName}`

#### 3. **Enhanced Topology Analysis**
**Restructured from 2 to 3 sub-components**:

**Before (HRP v1.0)**:
- 50% Blast radius
- 50% Supply chain (mixed together)

**After (HRP v2.0)**:
- 40% Blast radius (exponential entity count)
- 35% Connectivity depth (BFS graph traversal, 3-hop max)
- 25% Critical path (databases, services, K8s detection)

#### 4. **Aging Component Redesign** (5% Weight - Reduced)
**Changes**:
- Weight reduced from 15% to 5% (de-emphasized)
- Now uses **first-seen timestamp** (when Dynatrace detected vulnerability)
- Continuous time-weighted penalty: `(days/365) × severity_weight × 0.7`

#### 5. **PDF Generator Updates**
**Assessment Methodology Page** completely rewritten for HRP v2.0:
- Full mathematical formulas with subscripts and superscripts
- Detailed component breakdown with weights
- **Real calculation example** showing 70 vulnerabilities → 63.75 score
- Sensitivity explanation: "5-8 points per 10 vulnerabilities"
- Power-law dampening explanation

#### 6. **Process Group Filtering Improvements**
**Problem**: When filtering by `process_group` IDs, report included unrelated entities

**Solution**: Enhanced `collect_all_data()` to filter process groups collection:
- Exact PG ID matching
- Automatic PGI (Process Group Instance) inclusion for parent PGs
- Clean entity list (only filtered entities in report)

### Configuration Updates

**New HRP v2 Section** in config.yaml:
```yaml
hrp_v2:
  # Component weights (must sum to 1.0)
  vulnerability_weight: 0.60
  supply_chain_weight: 0.20  # NEW - standalone component
  topology_weight: 0.15
  aging_weight: 0.05
  
  # Vulnerability scoring
  dampening_function: "power"
  dampening_exponent: 0.75
  max_theoretical_score: 300
  exploitability_multiplier: 3.0
  cve_multiplier: 2.2
```

### Breaking Changes

⚠️ **Configuration Changes Required**:
- If upgrading from HRP v1.0, add `hrp_v2` section to config.yaml
- Set `risk_model: "HRP2"` to use new model
- Old `risk_model: "HRP"` still works (uses v1.0)

⚠️ **JSON Report Structure**:
- HRP v2 reports include 4 components (was 3)
- New field: `supply_chain_score`
- `model` field shows "HRP2" (was "HRP")

---

*This document serves as comprehensive session memory for future ASTRA development. Refer to this file when resuming work or onboarding new contributors.*

