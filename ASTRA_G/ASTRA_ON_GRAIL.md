# ASTRA on GRAIL - Holistic Risk Posture Assessment

**Version:** 2.0  
**Implementation:** JavaScript tiles on Dynatrace GRAIL  
**Last Updated:** January 2026

---

## Table of Contents
1. [Executive Summary](#executive-summary)
2. [The Algorithm: Risk Concentration Model](#the-algorithm-risk-concentration-model)
3. [Business Risk Assessment](#business-risk-assessment)
4. [Vulnerability Prioritization](#vulnerability-prioritization)
5. [Dashboard Tiles](#dashboard-tiles)
6. [Dashboard Variables](#dashboard-variables)
7. [Technical Implementation](#technical-implementation)
8. [Use Cases & Workflows](#use-cases--workflows)

---

## Executive Summary

**ASTRA (Application Security Threat & Risk Assessment)** is a holistic vulnerability risk scoring system built on Dynatrace GRAIL that measures **Potential Business Impact from Security Exposure**.

### What Makes ASTRA Different?

Unlike traditional vulnerability scoring (CVSS), ASTRA measures business impact by combining:
- **Vulnerability Severity**: Not just scores, but exploitability and real-world impact
- **Supply Chain Risk**: How widespread is the exposure across your software components?
- **Topology Impact**: What critical services/data are at risk if breached?
- **Exposure Duration**: How long have we been vulnerable?

### Key Features

✅ **Risk Concentration Model**: 60% weight on top-10 vulnerabilities drives prioritization  
✅ **CVE Exclusion Control**: Model "what-if" scenarios by excluding remediated CVEs  
✅ **Baseline Calibration**: Automatic calculation of worst-case scenarios  
✅ **Chunked Processing**: Handles 486+ CVE exclusions without DQL limits  
✅ **Real-time GRAIL Data**: Direct integration with Dynatrace vulnerability events

---

## The Algorithm: Risk Concentration Model

### Core Philosophy

**The worst vulnerabilities matter most.** 

ASTRA uses a **Risk Concentration Model** that heavily weights the top-10 most dangerous vulnerabilities. This ensures that:
1. Remediating critical vulnerabilities causes dramatic score improvements
2. Noise from low-risk CVEs doesn't obscure real threats
3. Prioritization is data-driven and actionable

### Mathematical Foundation

#### Step 1: Calculate Vulnerability Contribution

Each vulnerability receives a **contribution score**:

```
vuln_contribution = davis_score × exploit_factor × cve_factor

Where:
- davis_score = Dynatrace Davis AI assessment (0-10)
- exploit_factor = 3.0 if public exploit available, else 1.0
- cve_factor = 2.2 if CVE ID assigned, else 1.0
```

**Why this matters:**
- High severity + public exploit + CVE = 66x more impactful than low severity
- Reflects real-world exploitability, not just theoretical risk

#### Step 2: Establish Baseline Metrics

Query **all open vulnerabilities** (no exclusions) to establish stable reference:

```javascript
baseline_sum = Σ(all vulnerability contributions)
baseline_top10_sum = Σ(top 10 vulnerability contributions)
```

**This baseline is stable** - it represents the "worst case" security posture.

#### Step 3: Calculate Current Metrics

Apply CVE exclusions (if `$CVE_flag = "ON"`) to model remediated state:

```javascript
current_sum = Σ(remaining vulnerability contributions)
current_top10_sum = Σ(remaining top 10 contributions)
```

#### Step 4: Risk Concentration Score

```javascript
// Component 1: Total risk as % of baseline
total_risk_score = (current_sum / baseline_sum) × 100

// Component 2: Top-10 concentration as % of baseline
concentration_score = (current_top10_sum / baseline_top10_sum) × 100

// Final vulnerability score (60% weight on top-10)
vuln_score = (0.40 × total_risk_score) + (0.60 × concentration_score)
```

**Why 60% weight on top-10?**
- Removing a top-10 vulnerability causes immediate, visible impact
- Removing 100 low-risk CVEs has minimal impact
- Drives focus to what matters: **fix the worst first**

### Full HRP v2.0 Formula

```
HRP_Score = (W₁ × S_vuln) + (W₂ × S_supply) + (W₃ × S_topo) + (W₄ × S_aging)

Default Weights:
- W₁ = 0.60 (Vulnerability Score)
- W₂ = 0.20 (Supply Chain)
- W₃ = 0.15 (Topology/Blast Radius)
- W₄ = 0.05 (Aging)
```

#### Component Formulas

**S_supply (Supply Chain Risk):**
```javascript
vulnerable_ratio = vulnerable_libraries / total_libraries
S_supply = min(100, 100 × vulnerable_ratio^0.7)
```

**S_topo (Topology/Blast Radius):**
```javascript
blast_score = 100 × (1 - e^(-0.05 × total_related_entities))
critical_path_score = (critical_entities / total_entities) × 100
S_topo = (0.40 × blast_score) + (0.35 × connectivity_score) + (0.25 × critical_path_score)
```

**S_aging (Vulnerability Aging):**
```javascript
Aging Bands:
- 0-30 days:    5%
- 31-90 days:   15%
- 91-180 days:  35%
- 181-365 days: 60%
- 366-730 days: 85%
- >730 days:    100%
```

---

## Business Risk Assessment

### What is "Business Risk"?

Business risk is **not** just technical severity. It's the answer to:

> *"If this vulnerability is exploited, what is the potential impact on business operations, revenue, reputation, and customer trust?"*

### The Four Dimensions of Business Risk

#### 1. **Exploitability Risk (Vulnerability Score - 60%)**

**Question:** *How easy is it for an attacker to exploit this?*

**Factors:**
- **Severity**: CRITICAL vulnerabilities with CVSS 9.0+ scores
- **Exploit Availability**: Public exploit code = imminent threat
- **CVE Assignment**: Tracked vulnerabilities = widespread knowledge
- **Davis AI Assessment**: Real-world context from Dynatrace AI

**Business Impact:**
- Public exploits mean attackers have ready-made tools
- CVE publicity attracts attention from threat actors
- High severity = low skill barrier for attackers

**Example:**
```
Log4Shell (CVE-2021-44228):
- Davis Score: 10.0
- Exploit Available: YES (3.0x)
- CVE Assigned: YES (2.2x)
- Contribution: 10.0 × 3.0 × 2.2 = 66.0

Generic Low Severity:
- Davis Score: 2.0
- No Exploit: (1.0x)
- No CVE: (1.0x)
- Contribution: 2.0 × 1.0 × 1.0 = 2.0
```

#### 2. **Supply Chain Risk (20%)**

**Question:** *How widespread is this weakness across our software foundation?*

**Factors:**
- **Vulnerable Library Ratio**: % of libraries with known vulnerabilities
- **Dependency Depth**: Direct vs transitive dependencies
- **Library Usage**: How many process groups use this library?

**Business Impact:**
- Vulnerable libraries = attack surface in every application using them
- Transitive dependencies = hidden risk
- Popular libraries = widespread exposure

**Calculation:**
```javascript
// Example: 50 vulnerable libraries out of 200 total
vulnerable_ratio = 50 / 200 = 0.25 (25%)
supply_score = 100 × 0.25^0.7 = 33.5

// Power-law scaling means:
// 10% vulnerable = 20.0 score
// 50% vulnerable = 57.4 score
// 100% vulnerable = 100.0 score
```

#### 3. **Topology/Blast Radius Risk (15%)**

**Question:** *If breached, how much of our infrastructure is at risk?*

**Factors:**
- **Connected Entities**: Services, databases, hosts, apps, K8s workloads
- **Critical Path**: Are databases, services, or data assets connected?
- **Interconnectivity**: How tightly coupled are systems?

**Business Impact:**
- Database access = data breach risk
- Service connectivity = lateral movement potential
- K8s exposure = container escape risk
- High entity count = widespread compromise

**Calculation:**
```javascript
// Example: PGI with 50 related entities
blast_score = 100 × (1 - e^(-0.05 × 50)) = 91.8

// 10 entities = 39.3 score
// 50 entities = 91.8 score
// 100 entities = 99.3 score
```

#### 4. **Exposure Duration Risk (5%)**

**Question:** *How long have we been exposed to this threat?*

**Factors:**
- **Age in Days**: Time since first detection
- **Severity Weighting**: Critical vulns age faster
- **Remediation Window**: Industry standards (e.g., 30 days for CRITICAL)

**Business Impact:**
- Longer exposure = higher probability of discovery by attackers
- Aged vulnerabilities = organizational debt
- Reflects remediation velocity and process maturity

**Progressive Penalty:**
```
Recent (0-30 days):     5% - Acceptable response window
Moderate (31-90 days):  15% - Warning zone
Concerning (91-180):    35% - Breach of best practices
Severe (181-365):       60% - Significant exposure
Critical (>365):        85-100% - Organizational risk
```

### Risk Band Interpretation

| Score Range | Risk Level | Business Interpretation |
|-------------|-----------|-------------------------|
| 90-100 | **CRITICAL** | Imminent business disruption risk. Board-level escalation. |
| 70-89 | **HIGH** | Material business risk. C-suite awareness required. |
| 50-69 | **MEDIUM** | Moderate risk. Active management needed. |
| 30-49 | **LOW** | Acceptable risk. Continue monitoring. |
| 0-29 | **MINIMAL** | Negligible business impact. Normal operations. |

---

## Vulnerability Prioritization

### The Prioritization Problem

Security teams face:
- **1000s of vulnerabilities** across infrastructure
- **Limited resources** for remediation
- **Pressure from multiple stakeholders**
- **Unclear impact** of individual fixes

**Traditional approach:** Sort by CVSS score → fix highest first

**Problem:** CVSS doesn't account for:
- Your specific environment
- Exploitability in the wild
- Business context
- Interconnected systems

### ASTRA's Prioritization Mechanism

#### 1. **Risk Concentration Model (Top-10 Focus)**

The algorithm **automatically identifies** the 10 most dangerous vulnerabilities based on:
- Contribution score (severity × exploit × CVE)
- Real-world exploitability
- Davis AI assessment

**Impact:** Removing any top-10 vulnerability causes **dramatic score drop** (60% weight).

#### 2. **CVE Exclusion "What-If" Modeling**

Use `$Exclude_CVE` and `$CVE_flag` to model remediation scenarios:

```
Scenario 1: Baseline (flag OFF)
- Shows current risk state
- Score: 85.5 (HIGH)

Scenario 2: Exclude Top-3 CVEs (flag ON)
- Models: CVE-2024-21511, CVE-2021-44228, CVE-2024-21508
- Score: 52.3 (MEDIUM)
- Impact: 33.2 point drop = 38.8% improvement

Scenario 3: Exclude Low-Risk CVEs (flag ON)
- Models: 50 low-severity CVEs
- Score: 84.7 (HIGH)
- Impact: 0.8 point drop = 0.9% improvement
```

**Insight:** Top-3 have 43x more impact than bottom-50.

#### 3. **Component Breakdown Analysis**

**HRP Breakdown Tile** shows contribution by component:

```
Vulnerability Score: 45% of total HRP
Supply Chain: 30%
Topology: 18%
Aging: 7%
```

**Action:** Focus on vulnerability remediation (highest contributor).

#### 4. **Top-10 Vulnerability Table**

**Vuln Breakdown Tile** shows:
- Exact CVE IDs
- Contribution scores
- Exploit availability
- Related entities
- Age in days

**Prioritization Criteria:**
1. **Contribution Score** (highest first)
2. **Exploit Available** (yes before no)
3. **Related Entities** (more connections = higher blast radius)
4. **Age** (older = higher urgency)

### Prioritization Workflow

#### Step 1: Identify Top-10 Vulnerabilities
→ View **Vulnerability Breakdown** tile  
→ Sort by contribution score (automatic)

#### Step 2: Assess Business Context
→ Check related entities (databases, services)  
→ Review exploit availability  
→ Evaluate age (>90 days = high urgency)

#### Step 3: Model Remediation Impact
→ Add top-3 CVEs to `$Exclude_CVE`  
→ Set `$CVE_flag = "ON"`  
→ Observe score drop

#### Step 4: Prioritize by Impact
→ Fix vulnerabilities with highest score impact first  
→ Focus on top-10 over long tail  
→ Re-run assessment after remediation

#### Step 5: Track Progress
→ Use **Summary Tile** for executive reporting  
→ Monitor component breakdown trends  
→ Validate score improvements

---

## Dashboard Tiles

### 1. **Executive Summary Tile** (`summary.js`)

**Purpose:** C-suite/executive reporting with full risk assessment

**Implementation:**
- Risk Concentration Model scoring
- Component breakdown (V/T/S/A)
- Key findings section
- Recommendations by risk level

**Output:** Markdown report with:
- Overall HRP score (0-100) with risk level
- Total vulnerabilities by severity
- Infrastructure impact metrics
- Supply chain risk assessment
- Recommendations based on risk band

**Use Case:** Monthly security reviews, board presentations

**Data Sources:**
- `fetchTopologyScoreBlastScoreAge()`: Main vulnerability + topology data
- `fetchBaselineVulnDistribution()`: Baseline calibration (no exclusions)
- `fetchVulnDistribution()`: Current state (with exclusions)
- `fetchVulnLibraryRatio()`: Software component data

---

### 2. **HRP Score Only** (`hrp_score_only.js`)

**Purpose:** Single-value display of overall HRP risk score

**Implementation:**
- Risk Concentration Model
- Minimal calculation overhead
- Production-ready (no debug logs)

**Output:** Single value with label
```json
[{ "value": 77.45, "label": "HRP v2.0 Score" }]
```

**Use Case:** Dashboard KPI tile, executive summary

---

### 3. **HRP Score Only AUTO** (`hrp_score_only_AUTO.js`)

**Purpose:** Debug version with detailed component breakdown

**Implementation:**
- Same as `hrp_score_only.js`
- **Plus:** Console logging for troubleshooting
- **Plus:** Extended label with component scores

**Output:** Single value with detailed label
```json
[{
  "value": 77.45,
  "label": "HRP v2.0 (15.2% ↓ | V:85.3 T:72.1 S:45.2 A:22.5 | Top10:88.5%)"
}]
```

**Console Output:**
```
=== DEBUG: Vulnerability Metrics ===
BASELINE: { baseline_sum: 11257, baseline_top10_sum: 575 }
CURRENT: { current_sum: 10564, current_top10_sum: 575 }
VULN SCORE: 77.92 | Band: High
...
```

**Use Case:** Development, troubleshooting, validation

---

### 4. **HRP Component Breakdown** (`hrp_breakdown.js`)

**Purpose:** Visualize contribution % of each HRP component

**Implementation:**
- Risk Concentration Model
- Calculates contribution ratios
- Bar chart visualization

**Output:** Array of components with percentages
```json
[
  { "component": "Vulnerability Score", "contribution_ratio": 45.2 },
  { "component": "Supply Chain Risk", "contribution_ratio": 30.1 },
  { "component": "Topology/Blast Radius", "contribution_ratio": 18.5 },
  { "component": "Vulnerability Aging", "contribution_ratio": 6.2 },
  { "component": "MAX HRP v2.0", "contribution_ratio": 100.0 }
]
```

**Use Case:** Understand which factors drive risk, identify focus areas

---

### 5. **HRP v2.0 Tile** (`tile_hrpv2.js`)

**Purpose:** Full HRP calculation with JSON output for custom visualization

**Implementation:**
- Risk Concentration Model
- Returns structured JSON with all components
- Metadata for dashboards

**Output:**
```json
{
  "hrp_v2_score": 77.45,
  "risk_level": "HIGH",
  "breakdown": {
    "vulnerability_component": "85.30",
    "supply_chain_component": "45.20",
    "topology_component": "72.10",
    "aging_component": "22.50"
  },
  "metadata": {
    "total_vulnerabilities": 1247,
    "vulnerable_libraries": 45,
    "total_libraries": 150
  }
}
```

**Use Case:** Custom dashboards, API integration, external reporting

---

### 6. **Top 10 Vulnerabilities Breakdown** (`vuln_breakdown.js`)

**Purpose:** Detailed table of most critical vulnerabilities

**Implementation:**
- Fetches top 10 by contribution score
- CVE exclusion support
- Rich metadata per vulnerability

**Output:** Array of vulnerabilities
```json
[
  {
    "rank": 1,
    "vulnerability_id": "SNYK-JS-...",
    "vulnerability_url": "https://...",
    "title": "Arbitrary Code Injection in express",
    "severity": "CRITICAL",
    "risk_score": 66.0,
    "davis_score": 10.0,
    "cvss_score": 9.8,
    "cve_id": "CVE-2024-21511",
    "exploit_available": "⚠️ YES",
    "exposure": "🌐",
    "age_days": 127,
    "affected_component": "express",
    "component_version": "4.17.1",
    "related_services": 12,
    "related_databases": 3
  },
  ...
]
```

**Table Columns:**
- Rank (1-10)
- Vulnerability ID (clickable link)
- Title
- Severity badge
- Risk score (contribution)
- Exploit status
- Exposure (public/internal)
- Age (days)
- Affected component + version
- Related infrastructure

**Use Case:** Prioritization meetings, remediation tracking, incident response

---

### 7. **Vulnerability Distribution** (`vuln_distrib.js`)

**Purpose:** Bar chart showing vulnerability counts by severity

**Implementation:**
- Simple count aggregation
- CVE exclusion support
- Percentage calculations

**Output:** Array for bar chart
```json
[
  { "severity": "CRITICAL", "count": 15, "percentage": "1.2" },
  { "severity": "HIGH", "count": 234, "percentage": "18.8" },
  { "severity": "MEDIUM", "count": 678, "percentage": "54.4" },
  { "severity": "LOW", "count": 298, "percentage": "23.9" },
  { "severity": "NONE", "count": 22, "percentage": "1.7" }
]
```

**Use Case:** Severity distribution overview, trend analysis

---

## Dashboard Variables

### Core Filters

#### `$Tag_Filter`
- **Type:** Dropdown
- **Values:** `["ON", "OFF"]`
- **Default:** `"OFF"`
- **Purpose:** Enable/disable tag-based filtering
- **Impact:** When ON, only entities matching `$Tag_Key:$Tag_Value` are included

#### `$Tag_Key`
- **Type:** Text Input
- **Default:** `"environment"`
- **Purpose:** Tag key for filtering (e.g., "environment", "team", "criticality")
- **Example:** `"environment:production"`, `"team:platform"`

#### `$Tag_Value`
- **Type:** Text Input
- **Default:** `"production"`
- **Purpose:** Tag value for filtering
- **Note:** Used only when `$Tag_Filter = "ON"`

#### `$process_name_contains`
- **Type:** Text Input / Dropdown
- **Default:** `"ALL"`
- **Purpose:** Filter by process group instance name
- **Example:** `"payment-service"`, `"api-gateway"`, `"ALL"`

#### `$Severity`
- **Type:** Multi-select
- **Values:** `["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "ALL"]`
- **Default:** `["CRITICAL", "HIGH", "MEDIUM", "LOW"]`
- **Purpose:** Filter vulnerabilities by severity level

---

### CVE Exclusion Controls

#### `$Exclude_CVE`
- **Type:** Text Array
- **Format:** Comma-separated CVE IDs
- **Example:** `"CVE-2024-21511,CVE-2021-44228,CVE-2024-21508"`
- **Purpose:** Model remediation scenarios by excluding specific CVEs
- **Limit:** Unlimited (chunking handles 486+ CVEs)
- **Note:** Only applied when `$CVE_flag = "ON"`

#### `$CVE_flag`
- **Type:** Dropdown
- **Values:** `["ON", "OFF"]`
- **Default:** `"OFF"`
- **Purpose:** Toggle CVE exclusions on/off
- **Behavior:**
  - `"OFF"`: Show baseline risk (all vulnerabilities)
  - `"ON"`: Show risk after excluding CVEs in `$Exclude_CVE`

**Use Case:**
```
Step 1: Set $CVE_flag = "OFF" → See current risk: 85.5
Step 2: Add top-3 CVEs to $Exclude_CVE
Step 3: Set $CVE_flag = "ON" → See improved risk: 52.3
Step 4: Decision: Prioritize these 3 CVEs (38.8% improvement)
```

---

### HRP Weights (Advanced)

#### `$HRP_Vuln_Weight`
- **Type:** Decimal (0.0 - 1.0)
- **Default:** `0.60`
- **Purpose:** Weight for vulnerability component
- **Recommendation:** Keep at 0.60 (primary risk driver)

#### `$HRP_Supply_Weight`
- **Type:** Decimal (0.0 - 1.0)
- **Default:** `0.20`
- **Purpose:** Weight for supply chain risk component
- **Recommendation:** 0.15-0.25 depending on environment

#### `$HRP_Topology_Weight`
- **Type:** Decimal (0.0 - 1.0)
- **Default:** `0.15`
- **Purpose:** Weight for topology/blast radius component
- **Recommendation:** Increase for highly interconnected systems

#### `$HRP_Aging_Weight`
- **Type:** Decimal (0.0 - 1.0)
- **Default:** `0.05`
- **Purpose:** Weight for vulnerability aging component
- **Recommendation:** Keep low (aging is a multiplier, not primary risk)

**Note:** Weights should sum to 1.0 for proper scoring.

---

### Environment Configuration

#### `$Environment_url`
- **Type:** Text Input
- **Format:** Dynatrace environment URL
- **Example:** `"https://abc12345.live.dynatrace.com/"`
- **Purpose:** Generate clickable links to vulnerability details
- **Note:** Must include trailing slash

---

## Technical Implementation

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Dynatrace Dashboard                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Summary Tile │  │  HRP Score   │  │   Vuln Top10 │  │
│  │ (summary.js) │  │(hrp_score.js)│  │(vuln_break.js)│  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│          Dynatrace Query Execution Client               │
│              (@dynatrace-sdk/client-query)              │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                      GRAIL Storage                       │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │  Security Events (VULNERABILITY_STATE_REPORT)      │ │
│  ├────────────────────────────────────────────────────┤ │
│  │  - vulnerability.id, title, severity, cvss         │ │
│  │  - vulnerability.davis_assessment.*                │ │
│  │  - vulnerability.references.cve                    │ │
│  │  - affected_entity.vulnerable_component.*          │ │
│  │  - related_entities.{services,databases,hosts}     │ │
│  └────────────────────────────────────────────────────┘ │
│                                                          │
│  ┌────────────────────────────────────────────────────┐ │
│  │  Topology (dt.entity.*)                            │ │
│  ├────────────────────────────────────────────────────┤ │
│  │  - dt.entity.process_group_instance                │ │
│  │  - dt.entity.host                                  │ │
│  │  - dt.entity.software_component                    │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Key Design Decisions

#### 1. **Chunked CVE Exclusion**

**Problem:** DQL has expression depth limits (~50 `in()` checks)

**Solution:** Split CVE list into chunks of 50, apply multiple filters with `AND` logic

```javascript
const chunks = [];
for (let i = 0; i < cveList.length; i += 50) {
  const chunk = cveList.slice(i, i + 50);
  const cveChecks = chunk.map(c => `in("${c}", vulnerability.references.cve)`).join(' or ');
  chunks.push(`not(${cveChecks})`);
}
cveExclusionFilter = `| filter ${chunks.join(' and ')}`;
```

**Result:** Can process 486+ CVEs without DQL errors

#### 2. **Flag-Based Control**

**Problem:** Users wanted to maintain CVE list but toggle its application

**Solution:** `$CVE_flag` variable controls whether exclusions apply

```javascript
if (cve_flag === "ON" && excludeCveStr && ...) {
  // Build chunked exclusion filters
} else {
  // No filtering - baseline state
}
```

**Result:** Easy A/B comparison between baseline and remediated states

#### 3. **Baseline Stability**

**Problem:** Original algorithm recalculated baseline on every execution

**Solution:** Separate baseline query (no exclusions) establishes stable reference

```javascript
// Always run baseline first (no exclusions)
const baselineDistribution = await fetchBaselineVulnDistribution(...);
const baselineMetrics = calculateBaselineMetrics(baselineDistribution);

// Then run current state (with exclusions)
const currentDistribution = await fetchVulnDistribution(..., $CVE_flag, $Exclude_CVE);
const currentMetrics = calculateCurrentMetrics(currentDistribution);
```

**Result:** Consistent scoring, clear before/after comparison

---

### DQL Query Pattern

All tiles follow this structure:

```dql
fetch events
| filter event.kind=="SECURITY_EVENT"
| filter event.category=="VULNERABILITY_MANAGEMENT"
| filter event.type=="VULNERABILITY_STATE_REPORT_EVENT"
| filter vulnerability.resolution.status == "OPEN"
| filter vulnerability.mute.status == "NOT_MUTED"
| dedup vulnerability.id, affected_entity.id

${cveExclusionFilter}  // Applied only if CVE_flag = "ON"

| expand pid=affected_entity.affected_processes.ids
| lookup [fetch dt.entity.process_group_instance ...] 
| filter (tag filters AND process name filters)
| dedup vulnerability.id, pid

| fieldsAdd has_exploit=if(vulnerability.davis_assessment.exploit_status=="AVAILABLE", 3.0, else:1.0)
| fieldsAdd has_cve=if(isNotNull(vulnerability.references.cve), 2.2, else:1.0)
| fieldsAdd vuln_contribution=vulnerability.davis_assessment.score * has_exploit * has_cve

| summarize ...
```

---

## Use Cases & Workflows

### Use Case 1: Executive Risk Reporting

**Persona:** CISO, Security Director

**Workflow:**
1. Open dashboard with default filters (`$Tag_Filter = "OFF"`, `$CVE_flag = "OFF"`)
2. View **Executive Summary** tile for full risk assessment
3. Note HRP score and risk level
4. Review key findings and recommendations
5. Export markdown for board presentation

**Output:** 
- HRP Score: 85.5 (HIGH)
- Recommendation: "Address all CRITICAL and HIGH severity vulnerabilities with available exploits"

---

### Use Case 2: Vulnerability Prioritization

**Persona:** Security Engineer, DevSecOps

**Workflow:**
1. View **Top 10 Vulnerabilities Breakdown** tile
2. Sort by contribution score (automatic)
3. Identify top-3 CVEs with highest impact:
   - CVE-2024-21511 (contribution: 66.0)
   - CVE-2021-44228 (contribution: 66.0)
   - CVE-2024-21508 (contribution: 66.0)
4. Add to `$Exclude_CVE`: `"CVE-2024-21511,CVE-2021-44228,CVE-2024-21508"`
5. Set `$CVE_flag = "ON"`
6. Observe score drop: 85.5 → 52.3 (38.8% improvement)
7. Create remediation tickets prioritized by impact

---

### Use Case 3: Remediation Impact Validation

**Persona:** Platform Team, SRE

**Workflow:**
1. Before remediation: `$CVE_flag = "OFF"` → Baseline: 85.5
2. Patch top-3 vulnerabilities in production
3. Add patched CVEs to `$Exclude_CVE`
4. Set `$CVE_flag = "ON"` → Projected: 52.3
5. Wait 24h for Dynatrace re-scan
6. Set `$CVE_flag = "OFF"` → Actual: 53.1
7. Validate: Actual (53.1) ≈ Projected (52.3) ✅

**Result:** Confirmed remediation impact, validated process

---

### Use Case 4: Environment-Specific Risk Assessment

**Persona:** Security Architect

**Workflow:**
1. Set `$Tag_Filter = "ON"`
2. Set `$Tag_Key = "environment"`
3. Set `$Tag_Value = "production"`
4. View HRP score for production only: 88.2 (CRITICAL)
5. Change `$Tag_Value = "staging"`
6. View HRP score for staging: 45.3 (MEDIUM)
7. Prioritize production remediations

---

### Use Case 5: Supply Chain Risk Analysis

**Persona:** Application Security Team

**Workflow:**
1. View **HRP Component Breakdown** tile
2. Observe: Supply Chain = 35% of total risk
3. Navigate to library inventory
4. Identify: 45 of 150 libraries vulnerable (30%)
5. Focus on most-used libraries:
   - express 4.17.1 → Upgrade to 4.19.2
   - log4j 2.14.1 → Upgrade to 2.23.1
6. Re-run assessment after upgrades
7. Validate supply chain score improvement

---

### Use Case 6: Continuous Risk Monitoring

**Persona:** Security Operations Center (SOC)

**Workflow:**
1. Dashboard displayed on SOC wallboard
2. **HRP Score Only** tile shows real-time risk: 77.5
3. Alert triggered when score exceeds 85.0
4. SOC analyst investigates:
   - New vulnerability discovered (CVE-2026-XXXXX)
   - Contribution score: 66.0 (top-10 entry)
5. Escalate to security team
6. Track remediation progress via score trend

---

### Use Case 7: Incident Response

**Persona:** Incident Response Team

**Workflow:**
1. Zero-day vulnerability announced (e.g., Log4Shell)
2. Search `$Exclude_CVE` for CVE-2021-44228
3. Set `$CVE_flag = "ON"` (exclude it temporarily)
4. View **Top 10 Vulnerabilities** without Log4Shell
5. Identify next most critical vulnerabilities
6. Triage: Patch Log4Shell first, then CVE-2024-21511
7. Monitor score improvement after patches deployed

---

## Appendix

### Troubleshooting

#### Score Not Changing When Excluding CVEs

**Symptoms:** Adding CVEs to `$Exclude_CVE` doesn't affect score

**Diagnosis:**
1. Check `$CVE_flag` → Must be `"ON"`
2. Check CVE format → Must be exact match (e.g., `"CVE-2024-21511"`)
3. Check console logs in `hrp_score_only_AUTO.js`:
   ```
   CVE Exclusion Flag: OFF - Exclusions NOT applied
   ```

**Solution:** Set `$CVE_flag = "ON"`

---

#### Score Increasing When Excluding High-Risk CVEs

**Symptoms:** Excluding top-10 CVEs causes score to go UP

**Root Cause:** Alphabetical truncation (fixed in v2.0)

**Diagnosis:** Check console for:
```
Applied 1 CVE filter chunks (50 total CVEs)  // Only 50 applied
```

**Solution:** Upgrade to chunked implementation (already deployed)

---

#### DQL Timeout Errors

**Symptoms:** Query execution timeout after 60 seconds

**Diagnosis:**
1. Check number of process groups in scope
2. Check lookups (software components, topology)
3. Check CVE exclusion chunks

**Solution:**
- Reduce scope with `$process_name_contains` filter
- Enable `$Tag_Filter` to narrow results
- Increase timeout in query (already 60s max)

---

### Future Enhancements

#### Planned Features

1. **Machine Learning Risk Prediction**
   - Train model on historical remediation data
   - Predict likelihood of exploitation
   - Recommend optimal remediation sequence

2. **Cost-Benefit Analysis**
   - Calculate remediation effort estimates
   - ROI for each vulnerability fix
   - Budget allocation recommendations

3. **Automated Remediation Tracking**
   - Integration with ticketing systems
   - Automatic CVE exclusion when patched
   - Remediation velocity metrics

4. **Threat Intelligence Integration**
   - Real-time threat actor activity feeds
   - Zero-day exploit detection
   - Dark web monitoring for CVE mentions

5. **Compliance Reporting**
   - PCI-DSS vulnerability remediation timelines
   - SOC 2 evidence collection
   - NIST Cybersecurity Framework mapping

---

### References

- **Dynatrace GRAIL Documentation**: https://docs.dynatrace.com/docs/platform/grail
- **Dynatrace Query Language (DQL)**: https://docs.dynatrace.com/docs/platform/grail/dynatrace-query-language
- **Dynatrace Application Security**: https://docs.dynatrace.com/docs/platform-modules/application-security
- **Davis AI**: https://docs.dynatrace.com/docs/platform/davis-ai

---

## Change Log

### v2.0 (January 2026)
- ✅ Implemented Risk Concentration Model (60% weight on top-10)
- ✅ Added chunked CVE exclusion (handles 486+ CVEs)
- ✅ Added `$CVE_flag` control variable
- ✅ Fixed alphabetical truncation bug
- ✅ Baseline stability improvements
- ✅ Debug logging in AUTO version

### v1.5 (December 2025)
- Added supply chain risk component
- Topology blast radius calculation
- Aging penalty bands

### v1.0 (November 2025)
- Initial release
- Basic vulnerability scoring
- DQL-based implementation

---

**Maintained by:** ASTRA Development Team  
**Support:** security-engineering@company.com  
**License:** Internal Use Only
