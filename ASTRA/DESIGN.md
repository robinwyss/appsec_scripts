# ASTRA Phase 1 - Design Document

## Overview
ASTRA (Application Security Threat & Risk Assessment) Phase 1 generates comprehensive risk assessment reports for Dynatrace-monitored applications.

## Architecture

### Components

```
┌─────────────────────────────────────────────────────────────┐
│                     astra_phase1.py                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   │
│  │   Config     │   │  Data        │   │  Risk        │   │
│  │   Loader     │──▶│  Collector   │──▶│  Calculator  │   │
│  └──────────────┘   └──────────────┘   └──────────────┘   │
│                            │                    │          │
│                            ▼                    ▼          │
│                     ┌──────────────┐   ┌──────────────┐   │
│                     │  JSON        │   │  PDF         │   │
│                     │  Exporter    │   │  Generator   │   │
│                     └──────────────┘   └──────────────┘   │
└─────────────────────────────────────────────────────────────┘
         │                      │                 │
         ▼                      ▼                 ▼
   config.yaml         report_YYYYMMDD.json   report_YYYYMMDD.pdf
```

## Module Design

### 1. Configuration Module (`AstraConfig`)

**Responsibilities:**
- Load YAML configuration
- Validate settings
- Provide default values

**Configuration Structure:**
```yaml
dynatrace:
  environment: "https://tenant.dynatrace.com"
  api_token: "${DT_API_TOKEN}"
  verify_ssl: true

assessment:
  timeframe: "now-30d"  # 1 month of data
  risk_model: "CWRS"     # CWRS, REI, or HRP
  
filters:
  type: "process_group"  # process_group, host, application, management_zone
  ids: []                # Empty = all, or specific IDs
  management_zones: []   # Filter by MZ names
  tags: []               # Filter by tags

scoring:
  # CWRS weights (must sum to 100)
  vulnerability_weight: 40
  exploitability_weight: 25
  exposure_weight: 20
  criticality_weight: 15
  
output:
  json_path: "./reports"
  pdf_path: "./reports"
  filename_prefix: "astra_report"
```

### 2. Data Collector Module (`DataCollector`)

**Responsibilities:**
- Query Dynatrace API for vulnerability data
- Retrieve entity topology (Process Groups, Hosts, Services)
- Gather metadata (Management Zones, properties, relationships)
- Cache data to minimize API calls

**Key Methods:**
- `collect_security_problems()` - Get all security problems for timeframe
- `collect_process_groups()` - Get PG entities with relationships
- `collect_hosts()` - Get host entities with properties
- `collect_entity_relationships()` - Get topology connections (DB, services, etc.)
- `enrich_vulnerability_data()` - Add context to each vulnerability

**Data Structure (Enriched Vulnerability):**
```python
{
    "securityProblemId": "...",
    "cveIds": ["CVE-2023-xxxxx"],
    "packageName": "log4j",
    "severity": "CRITICAL",
    "cvssScore": 10.0,
    "riskAssessment": {...},
    "affectedEntities": [
        {
            "entityId": "PROCESS_GROUP-...",
            "entityName": "WebApp-Production",
            "entityType": "PROCESS_GROUP",
            "managementZones": ["Production", "CustomerFacing"],
            "properties": {
                "publicExposed": true,
                "hasDbConnection": true,
                "processCount": 12,
                "memoryTotal": 32768
            }
        }
    ],
    "firstSeenTimestamp": 1234567890,
    "lastUpdatedTimestamp": 1234567890,
    "remediationStatus": "OPEN"
}
```

### 3. Risk Calculator Module (`RiskCalculator`)

**Responsibilities:**
- Implement CWRS risk scoring algorithm
- Calculate risk scores per vulnerability
- Calculate aggregated risk score per entity
- Calculate overall application risk score

**Key Methods:**
- `calculate_vulnerability_severity_score(vuln)` - Returns 0-40 points
- `calculate_exploitability_score(vuln)` - Returns 0-25 points (NO attacks data)
- `calculate_exposure_score(entity)` - Returns 0-20 points
- `calculate_criticality_score(entity)` - Returns 0-15 points
- `calculate_entity_risk(entity, vulnerabilities)` - Aggregated entity risk
- `calculate_overall_risk(all_data)` - Single application risk indicator

**CWRS Implementation (Simplified for MVP):**

```python
def calculate_vulnerability_severity_score(vulnerabilities):
    """Calculate vulnerability score (0-40 points)"""
    score = 0
    for vuln in vulnerabilities:
        if vuln['severity'] == 'CRITICAL':
            score += 10
        elif vuln['severity'] == 'HIGH':
            score += 5
        elif vuln['severity'] == 'MEDIUM':
            score += 2
        elif vuln['severity'] == 'LOW':
            score += 0.5
    return min(score, 40)

def calculate_exploitability_score(vulnerabilities):
    """Calculate exploitability (0-25 points) - NO ATTACKS DATA"""
    score = 0
    for vuln in vulnerabilities:
        # Public exposure check from entity properties
        if vuln.get('affectedEntities', [{}])[0].get('properties', {}).get('publicExposed'):
            score += 10
        # Known exploit indicator from riskAssessment
        if vuln.get('riskAssessment', {}).get('exposure', {}).get('publicExploit'):
            score += 5
    return min(score, 25)

def calculate_exposure_score(entity):
    """Calculate attack surface (0-20 points)"""
    score = 0
    props = entity.get('properties', {})
    
    # Network entry points
    if props.get('publicExposed'):
        score += 2
    
    # Third-party libraries with vulnerabilities
    score += min(props.get('vulnerableLibraryCount', 0), 10)
    
    # Connected databases/systems
    score += props.get('connectedSystemsCount', 0) * 2
    
    return min(score, 20)

def calculate_criticality_score(entity):
    """Calculate system criticality (0-15 points)"""
    score = 0
    props = entity.get('properties', {})
    mzones = entity.get('managementZones', [])
    
    # Production/critical management zones
    if any('prod' in mz.lower() for mz in mzones):
        score += 5
    
    # Process count
    score += props.get('processCount', 0) // 10
    
    # Memory footprint
    if props.get('memoryTotal', 0) > 16384:  # > 16GB
        score += 5
    
    return min(score, 15)
```

### 4. JSON Exporter Module (`JsonExporter`)

**Responsibilities:**
- Export complete assessment data to JSON
- Include metadata (timestamp, config, version)
- Structure for easy comparison in Phase 2

**JSON Output Structure:**
```json
{
  "metadata": {
    "report_id": "astra_20260122_143022",
    "generated_at": "2026-01-22T14:30:22Z",
    "timeframe": "now-30d",
    "risk_model": "CWRS",
    "astra_version": "1.0.0"
  },
  "config": {
    "filters": {...},
    "scoring": {...}
  },
  "overall_risk": {
    "score": 67.5,
    "rating": "HIGH",
    "components": {
      "vulnerability_severity": 28,
      "exploitability": 15,
      "exposure": 14,
      "criticality": 10.5
    }
  },
  "entities": [
    {
      "entity_id": "PROCESS_GROUP-...",
      "entity_name": "WebApp-Production",
      "entity_type": "PROCESS_GROUP",
      "risk_score": 75.0,
      "risk_rating": "HIGH",
      "vulnerabilities": [
        {
          "securityProblemId": "...",
          "cveIds": ["CVE-2023-xxxxx"],
          "severity": "CRITICAL",
          "cvssScore": 10.0,
          "packageName": "log4j",
          "risk_contribution": 10
        }
      ]
    }
  ],
  "summary": {
    "total_entities": 15,
    "total_vulnerabilities": 42,
    "by_severity": {
      "CRITICAL": 3,
      "HIGH": 12,
      "MEDIUM": 20,
      "LOW": 7
    }
  }
}
```

### 5. PDF Generator Module (`PdfGenerator`)

**Responsibilities:**
- Generate professional PDF report
- Include charts and visualizations
- Organize by entity/PG hierarchy

**PDF Structure:**
1. **Executive Summary**
   - Overall Risk Score (large, prominent)
   - Risk rating badge (Low/Medium/High/Critical)
   - Total vulnerabilities by severity
   - Key findings (top 3 risks)

2. **Risk Score Breakdown**
   - Component scores (Vulnerability, Exploitability, Exposure, Criticality)
   - Bar chart visualization
   - Scoring methodology explanation

3. **Entity Risk Analysis**
   - For each entity (PG/Host):
     - Entity name and type
     - Risk score
     - Vulnerability count
     - Management zones
     - Properties (public-facing, DB connections, etc.)

4. **Vulnerability Details**
   - Grouped by entity
   - Table: CVE | Severity | Package | First Seen | Status
   - Risk contribution per vulnerability

5. **Appendix**
   - Configuration used
   - Timeframe
   - Methodology reference

**Libraries:**
- `reportlab` or `weasyprint` for PDF generation
- `matplotlib` for charts

## Implementation Strategy (MVP)

### Phase 1 - Minimal Viable Product

**Simplifications:**
1. **Single Risk Model:** Implement CWRS only (simplest)
2. **Filter Type:** Support Process Groups only
3. **No Attack Data:** Skip attack-based scoring (user requirement)
4. **Simple PDF:** Basic text layout, minimal charts
5. **Topology:** Basic relationship detection (DB connections via entity relationships)

**MVP Scope:**
- ✅ YAML config loading
- ✅ Query security problems for last 30 days
- ✅ Query process groups with properties
- ✅ Enrich vulnerabilities with entity data
- ✅ Calculate CWRS scores
- ✅ Export JSON report
- ✅ Generate basic PDF report
- ❌ Advanced filtering (defer to v1.1)
- ❌ REI/HRP models (defer to v1.1)
- ❌ Advanced visualizations (defer to v1.1)

### Dependencies

```
reportlab>=3.6.0
PyYAML>=6.0
requests>=2.28.0
pandas>=1.5.0
matplotlib>=3.6.0
```

## Testing Strategy

1. **Unit Tests:** Test each calculator function independently
2. **Integration Test:** Run against Dynatrace demo environment
3. **Output Validation:** Verify JSON schema and PDF generation

## Next Steps

1. Implement core modules
2. Create example config.yaml
3. Test with sample data
4. Generate first report
5. Iterate based on feedback
