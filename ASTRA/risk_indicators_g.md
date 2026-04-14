# Quantitative Risk Assessment for Dynatrace Grail

**Author Perspective:** CISSP with focus on Application Security  
**Objective:** Translate raw telemetry (software components, dependencies, traffic patterns) into Quantitative Risk Assessment  
**Data Source:** Dynatrace Grail data lakehouse

---

## Overview

The Dynatrace Grail data lakehouse enables querying three critical dimensions:
- **Vulnerability State** (Security Events)
- **Topology** (Smartscape/Entities)
- **Traffic/Usage** (Metrics/Spans)

By combining these dimensions, we move from **"theoretical risk" (CVSS)** to **"environmental risk"**.

---

## Solution 1: The Weighted Asset Exposure Index (WAEI)

### Format: 0% – 100% Risk Score
### Focus: Environmental Reachability and "Crown Jewel" Proximity

This indicator focuses on **Asset Value and Exposure (CISSP Domain 1)**. It assumes that a vulnerability is only as dangerous as the data it can touch and the people who can reach it.

### What it considers:

- **Public Exposure:** Does the application have an Entry Point service receiving traffic from public IP ranges?
- **Data Proximity:** Does the process group have a direct Smartscape dependency on a Database entity?
- **Vulnerability Density:** The count of Third-party and Code-level vulnerabilities.

### Indicator Components:

The score is a weighted average of three sub-scores:

1. **Exposure Factor (EF):** 1.0 if internet-facing, 0.2 if internal
2. **Impact Factor (IF):** 1.0 if connected to a database, 0.5 otherwise
3. **Vulnerability Magnitude (VM):** $\sum (\text{Davis Security Scores}) / \text{Total Components}$

### Formula:

$$Risk\% = (EF \times 40) + (IF \times 30) + (VM \times 30)$$

### DQL Insight:

Use the `dt.security_vulnerability` table in Grail to filter for:
- `vulnerability.assessment.exposure == "PUBLIC"`
- `vulnerability.assessment.data_assets == "REACHABLE"`

---

## Solution 2: The Runtime Exploitability Quotient (REQ)

### Format: 1 to 10 Scale
### Focus: Usage-based Risk and Active Attack Surface

As a CISSP, prioritize **Active Risk**. If a vulnerable library is sitting on a disk but never loaded into memory, the risk is lower than a library handling 1,000 requests per second.

### What it considers:

- **Runtime Usage:** Uses OneAgent "Vulnerable Functions" data to see if the specific code path is being executed
- **Throughput (Usage):** The volume of requests (RPM) flowing through the affected service
- **Exploit Availability:** Does the vulnerability have a known public exploit / bz checking the flag on Dznatrace API

### Indicator Components:

- **Active Status:** Score +2 if a vulnerable function is actively called (detected via Dynatrace RVA)
- **Traffic Multiplier:** Logarithmic scale of requests per minute: $log_{10}(RPM)$
- **Exploit Maturity:** Score +3 if a public exploit exists

### Indicator Logic:

A base score is taken from the highest Davis Security Score (DSS) in the application, then modified by:
- +1 for high traffic
- +2 for active code execution
- Capped at 10

---

## Solution 3: The Holistic Risk Posture (HRP)

### Format: 1 to 10 Scale
### Focus: Security Debt and "Blast Radius" (Topology)

This is a **"Management Level" indicator**. It treats the application as a node in a graph, assessing not just the app but its **Supply Chain** and its **Dependencies**.

### What it considers:

- **Software Component Aging:** Number of outdated libraries (Vulnerable vs. Non-vulnerable)
- **Transitive Risk:** Risks inherited from connected services (if Service A is clean but calls vulnerable Service B)
- **Remediation Velocity:** How long vulnerabilities have been "Open" in Grail

### Indicator Components:

| Component | Weight | Source in Dynatrace |
|-----------|--------|---------------------|
| Critical Vulnerabilities | 50% | `vulnerability.risk.level == "CRITICAL"` |
| Topology Risk | 25% | Sum of DSS of all downstream services (1st degree) |
| Aging Factor | 25% | `now() - vulnerability.first_occurrence` |

### Indicator Logic:

This score is calculated by aggregating all security events for the application's Process Group and its immediate neighbors in the Smartscape. It provides a **"Blast Radius" score**—if this app is compromised, how much of the environment is at risk?

---

## Comparison of Solutions

| Solution | Best For | Metric Type | Complexity |
|----------|----------|-------------|------------|
| **WAEI** | Compliance/Audit | 0-100% | Low (Static Context) |
| **REQ** | SOC/Incident Response | 1-10 | Medium (Runtime Context) |
| **HRP** | AppSec/CISO Reporting | 1-10 | High (Topological Context) |

---

## Implementation in Dynatrace Grail

To compare **Current vs. Past Risk**, store these calculated values as a **Custom Metric** or a **Security Attribute**.

### Example DQL for Trend Analysis:

```dql
// Example DQL for Trend Analysis
fetch security_events
| filter event.type == "VULNERABILITY_STATE_REPORT_EVENT"
| summarize { 
    RiskScore = avg(vulnerability.risk.score) 
  }, by:{ bin(timestamp, 1d), dt.entity.service }
```

This query provides time-series risk tracking across services.

---

## Next Steps

Consider implementing a complete DQL script for one of these solutions in a Dynatrace Notebook to visualize risk trends over time.

### Key Grail Tables to Query:

- `dt.security_vulnerability` - vulnerability data with environmental context
- `dt.entity.process_group_instance` - topology and dependencies
- `dt.service.key_requests` - traffic patterns and request volumes
- `dt.security_events` - security state changes over time

---

**Document Created:** January 22, 2026  
**Purpose:** Grail-based Risk Quantification Framework leveraging Dynatrace's data lakehouse capabilities
