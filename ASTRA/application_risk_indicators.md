# Three Application Risk Indicator Solutions for Dynatrace

As a CISSP analyzing application security risk, here are three distinct approaches to quantify application risk using Dynatrace observability data:

---

## **Solution 1: Composite Weighted Risk Score (CWRS)**
### Scale: 0-100% Risk

**Components & Weights:**

1. **Vulnerability Severity Score (40%)**
   - Critical CVEs: 10 points each
   - High CVEs: 5 points each
   - Medium CVEs: 2 points each
   - Low CVEs: 0.5 points each
   - Cap at 40 points

2. **Exploitability Factor (25%)**
   - Attack surface exposure (public-facing): +10 points
   - Recent attacks detected (from `/api/v2/attacks`): +5 points per attack type
   - Vulnerable components with known exploits: +5 points
   - Cap at 25 points

3. **Attack Complexity & Exposure (20%)**
   - Number of network-accessible entry points: +2 points per entry point
   - Third-party library count with vulnerabilities: +1 point per library
   - Connected databases/external systems: +2 points per connection
   - Cap at 20 points

4. **System Criticality & Usage (15%)**
   - Management Zone criticality (production/high-priority): +5 points
   - Process count (indicator of usage): +1 point per 10 processes
   - Memory footprint (high resource usage): +5 points if >16GB
   - Cap at 15 points

**Formula:** `Risk% = (V + E + A + S)`

**Temporal Comparison:** Calculate weekly snapshots, track delta percentage points

---

## **Solution 2: Risk Exposure Index (REI)**
### Scale: 1-10 Severity Rating

**Calculation Model:**

This uses a **logarithmic severity model** similar to earthquake magnitude scales, where each level represents exponentially higher risk.

**Base Calculation:**
```
REI = log₁₀(Total_Risk_Points + 1) × 1.5
```

**Risk Points Accumulation:**

1. **Vulnerability Impact Score (via CVSS)**
   - Use `riskAssessment` data from security problems
   - CVSS 9.0-10.0: 1000 points
   - CVSS 7.0-8.9: 500 points
   - CVSS 4.0-6.9: 100 points
   - CVSS 0.1-3.9: 10 points

2. **Blast Radius Multiplier**
   - Affected Process Groups (PGs): ×1.2 per PG
   - Affected Hosts: ×1.5 per host
   - Container Groups affected: ×1.3 per CGI

3. **Active Threat Intelligence**
   - Actual attacks in last 24h: +2000 points per attack
   - Security problems with "EXPLOIT_AVAILABLE": ×2 multiplier
   - CVEs on CISA KEV list: ×3 multiplier

4. **Remediation Debt**
   - Days since vulnerability discovered: +10 points per day for Critical, +5 for High
   - Number of unremediated items: +50 points each

**Scale Interpretation:**
- 1-3: Low Risk (minimal vulnerabilities, well-maintained)
- 4-6: Moderate Risk (some vulnerabilities, manageable exposure)
- 7-8: High Risk (significant vulnerabilities with exploitation potential)
- 9-10: Critical Risk (active threats, severe vulnerabilities, large blast radius)

**Temporal Comparison:** Track REI trend over time; ±1 point change is significant

---

## **Solution 3: Probabilistic Application Risk Model (PARM)**
### Scale: 0-100% Risk Probability

**Framework:** This models the **probability of a successful security incident** within the next 30 days.

**Formula:**
```
Risk% = [1 - ∏(1 - Pᵢ)] × Impact_Multiplier × 100
```

Where each Pᵢ represents probability of exploitation for each vulnerability path.

**Component Probabilities:**

1. **Per-Vulnerability Exploit Probability (Pᵥ)**
   ```
   Pᵥ = (CVSS_Exploitability/10) × Exposure_Factor × Age_Factor
   ```
   - **Exposure_Factor:**
     - Internet-facing: 0.9
     - Internal network: 0.3
     - Isolated/containerized: 0.1
   
   - **Age_Factor:**
     - <30 days: 0.3 (low awareness)
     - 30-90 days: 0.7 (exploit development period)
     - >90 days: 1.0 (weaponized exploits likely exist)

2. **Technology Stack Risk (Pₜ)**
   - Calculate from software component data:
   ```
   Pₜ = (Vulnerable_Components / Total_Components) × Severity_Weight
   ```
   - Severity_Weight = average CVSS of all vulnerabilities / 10

3. **Attack History Factor (Pₐ)**
   ```
   Pₐ = min(Recent_Attacks / 10, 0.5)
   ```
   - Capped at 50% contribution to avoid over-weighting

4. **Impact Multiplier (based on business criticality)**
   - Production + High Memory + Multiple PGs: 1.5×
   - Production: 1.2×
   - Development/Test: 0.8×

**Data Collection Strategy:**
- Query security problems with `riskAssessment` and `relatedEntities`
- Track attack data from `/api/v2/attacks` endpoint
- Monitor software component changes via PGI relationships
- Calculate daily for 30-day rolling comparison

**Temporal Analysis:**
- Daily snapshots stored in Grail
- Calculate risk velocity: `Δ%/Δt` (percentage points per day)
- Trigger alerts when risk increases >10% in 7 days

---

## **Implementation Recommendations**

**Best for Different Scenarios:**

- **CWRS (Solution 1)**: Best for **executive dashboards** - easy to understand, comprehensive coverage
- **REI (Solution 2)**: Best for **security operations teams** - emphasizes severity and active threats
- **PARM (Solution 3)**: Best for **risk management** - quantifies actual incident probability for insurance/audit purposes

**Dynatrace Grail Integration:**
All three can leverage:
- DQL queries for historical trending
- Security problem records with full metadata
- Entity relationships for blast radius calculation
- Attack data for threat intelligence
- Custom metrics/events stored as time series

**Key Advantage:** Each model is **data-driven and reproducible**, enabling objective period-over-period comparison and automation via the Dynatrace API your scripts already utilize.

---

## **Dynatrace API Endpoints Required**

Based on your existing `dynatrace_api.py`:

- `/api/v2/securityProblems` - vulnerability data with risk assessment
- `/api/v2/attacks` - active attack detection
- `/api/v2/entities` - process groups, hosts, software components
- `/api/v2/securityProblems/{id}/remediationItems` - remediation tracking
- `/api/v2/events` - process restart events (stability indicator)

---

**Document Created:** January 22, 2026  
**Purpose:** Application Risk Quantification Framework for Dynatrace Security Monitoring
