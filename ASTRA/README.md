# ASTRA - Application Security Threat & Risk Assessment

A comprehensive Python tool for quantifying application security risk using Dynatrace observability data.

## Overview

ASTRA implements four risk scoring models:
- **CWRS (Composite Weighted Risk Score)**: 0-100% scale - "What's our security posture?"
- **REI (Risk Exposure Index)**: 1-10 logarithmic scale - "How urgent is the threat?"
- **HRP v1.0 (Holistic Risk Posture)**: 1-10 scale - "How interconnected and aged is our risk?"
- **HRP v2.0 (Holistic Risk Posture v2)**: 0-100 scale - "What's the potential business damage if exploited?" ✨

### HRP v2.0: Business Impact Risk Assessment

HRP v2.0 measures **"Potential Business Impact from Security Exposure"** by answering:

1. **How easy to exploit?** (60% - Vulnerabilities)
   - Are there public exploits? CVE IDs? High severity?
   
2. **How widespread is the weakness?** (20% - Supply Chain)
   - What percentage of our software libraries are vulnerable?
   
3. **How much damage if breached?** (15% - Topology)
   - How many systems could be affected (blast radius)?
   - Are critical systems (databases, K8s) at risk?
   - How interconnected are vulnerable components?
   
4. **How long have we been exposed?** (5% - Aging)
   - How long have these vulnerabilities existed unpatched?

**Key Distinction**: HRP represents **exploitability likelihood multiplied by blast radius impact** - the potential operational and security damage if an attacker successfully exploited the identified vulnerabilities.

Supports multiple assessment phases:
- **Phase 1**: Current risk assessment with detailed scoring
- **Phase 2**: Temporal comparison and trend analysis (coming soon)

## Features

### Phase 1 - Current Risk Assessment
- Collects vulnerability data from Dynatrace over configurable timeframes (default: 30 days)
- **Four Risk Models:**
  - **CWRS (0-100%)**: Balanced weighted scoring
  - **REI (1-10)**: Logarithmic scale emphasizing severity
  - **HRP v1.0 (1-10)**: Topology-aware risk with aging
  - **HRP v2.0 (0-100)**: Business impact with 4-component model
- Uses **Davis Security Score** for context-aware vulnerability assessment
- **Auto-Dampening Optimization**: Automatically tune HRP v2.0 parameters for your environment
- Generates JSON report for historical tracking
- Produces professional PDF reports with methodology explanations

### Phase 2 - Comparative Assessment (Coming Soon)
- Compares current vs. previous assessments
- Highlights resolved vulnerabilities
- Tracks risk improvement metrics
- Shows risk trend analysis

## Installation

### Prerequisites
- Python 3.8+
- Access to Dynatrace environment
- Dynatrace API Token with permissions:
  - `securityProblems.read`
  - `entities.read`

### Setup

1. **Clone or navigate to the repository:**
```bash
cd /path/to/appsec_scripts
```

2. **Install dependencies:**
```bash
pip install -r ASTRA/requirements.txt
```

3. **Configure your assessment:**
```bash
cp ASTRA/config.example.yaml ASTRA/config.yaml
# Edit config.yaml with your Dynatrace details
```

4. **Set your API token:**
```bash
export DT_API_TOKEN="dt0c01.ABC123..."
```

## Usage

### Basic Usage

Run a Phase 1 assessment (default behavior):

```bash
python ASTRA/astra_report.py -c ASTRA/config.yaml
```

Or explicitly specify Phase 1:

```bash
python ASTRA/astra_report.py -c ASTRA/config.yaml --phase-1
# or use short form:
python ASTRA/astra_report.py -c ASTRA/config.yaml -1
```

### Phase 2 - Temporal Comparison (Coming Soon)

```bash
python ASTRA/astra_report.py -c ASTRA/config.yaml --phase-2
# Optional: specify baseline report for comparison
python ASTRA/astra_report.py -c ASTRA/config.yaml -2 --baseline reports/astra_report_20260122.json
```

### With Debug Logging

```bash
python ASTRA/astra_report.py -c ASTRA/config.yaml --debug
```

### HRP v2.0 Auto-Dampening Optimization 🎯

Automatically optimize dampening parameters for your environment:

```bash
python ASTRA/astra_report.py -c ASTRA/config.yaml -1 --hrp-dampen
# or use short form:
python ASTRA/astra_report.py -c ASTRA/config.yaml -1 -hd
```

This feature:
- Analyzes your vulnerability profile
- Tests 25 parameter combinations
- Recommends optimal dampening settings
- Places scores in actionable range (70-90)
- Ensures visible sensitivity to fixes (8-15 points)
- Avoids score saturation

**See [DAMPENING_OPTIMIZATION.md](DAMPENING_OPTIMIZATION.md) for detailed guide.**

### Configuration Options

Edit `config.yaml` to customize:

```yaml
# Target your Dynatrace environment
dynatrace:
  environment: "https://your-tenant.live.dynatrace.com"
  api_token: "${DT_API_TOKEN}"

# Set assessment timeframe and model
assessment:
  timeframe: "now-30d"  # Last 30 days
  risk_model: "REI"     # Options: "CWRS" or "REI"

# Filter entities
filters:
  type: "process_group"
  management_zones: ["Production"]  # Only production apps
  exploitability_weight: 25
  exposure_weight: 20
  criticality_weight: 15
```

## Output

### JSON Report
```json
{
  "metadata": {
    "report_id": "astra_20260122_143022",
    "generated_at": "2026-01-22T14:30:22Z",
    "risk_model": "CWRS"
  },
  "overall_risk": {
    "score": 67.5,
    "rating": "HIGH"
  },
  "entities": [...]
}
```

### PDF Report
Professional report including:
- Executive summary with overall risk score
- Risk component breakdown
- Vulnerability statistics by severity
- Entity-level risk details
- Detailed findings per entity

## Risk Scoring Methodology

### CWRS (Composite Weighted Risk Score)

The CWRS model calculates risk as:

```
Risk% = (V × 0.4) + (E × 0.25) + (A × 0.20) + (C × 0.15)
```

Where:
- **V** = Vulnerability Severity Score (0-40 points)
- **E** = Exploitability Factor (0-25 points)
- **A** = Attack Surface Exposure (0-20 points)
- **C** = System Criticality (0-15 points)

### Risk Ratings

| Score Range | Rating | Description |
|------------|--------|-------------|
| 70-100% | CRITICAL | Immediate action required |
| 50-69% | HIGH | Urgent remediation needed |
| 30-49% | MEDIUM | Scheduled remediation |
| 0-29% | LOW | Monitor and track |

## Directory Structure

```
ASTRA/
├── astra_phase1.py          # Main assessment script
├── config.example.yaml       # Example configuration
├── config.yaml              # Your configuration (git-ignored)
├── requirements.txt         # Python dependencies
├── DESIGN.md               # Technical design document
├── application_risk_indicators.md  # Risk methodology details
├── risk_indicators_g.md    # Grail-specific indicators
├── README.md               # This file
└── reports/                # Generated reports (created automatically)
    ├── astra_report_20260122_143022.json
    └── astra_report_20260122_143022.pdf
```

## Example Workflow

### Monthly Risk Assessment

```bash
#!/bin/bash
# monthly_assessment.sh

# Set environment
export DT_API_TOKEN="your-api-token"

# Run assessment
python ASTRA/astra_phase1.py -c ASTRA/config.yaml

# Archive report
REPORT_DATE=$(date +%Y%m)
mkdir -p archives/$REPORT_DATE
cp reports/astra_report_*.{json,pdf} archives/$REPORT_DATE/

echo "Assessment complete for $REPORT_DATE"
```

### Filtering by Management Zone

```yaml
# config.yaml
filters:
  management_zones: ["Production", "CustomerFacing"]
```

```bash
python ASTRA/astra_phase1.py -c ASTRA/config.yaml
```

## Troubleshooting

### API Connection Issues

```bash
# Test API connectivity
curl -H "Authorization: Api-Token $DT_API_TOKEN" \
  https://your-tenant.live.dynatrace.com/api/v2/securityProblems
```

### SSL Certificate Errors

Set `verify_ssl: false` in config.yaml for self-signed certificates.

### Large Environments

For environments with 100+ entities:
- Increase `max_entities_in_pdf` setting
- Consider filtering by management zone
- Use shorter timeframes (e.g., "now-7d")

## Roadmap

- [x] Phase 1: Initial risk assessment
- [ ] Phase 2: Comparative analysis
- [ ] REI (Risk Exposure Index) model
- [ ] HRP (Holistic Risk Posture) model
- [ ] Grail DQL integration
- [ ] Dashboard templates
- [ ] Automated scheduling
- [ ] Risk trend charts
- [ ] Email report delivery

## Contributing

This tool is built on the existing `dynatrace_api.py` framework. To extend:

1. Review [DESIGN.md](DESIGN.md) for architecture details
2. Test changes against Dynatrace demo environment
3. Update documentation

## References

- [Application Risk Indicators](application_risk_indicators.md) - Detailed methodology
- [Grail Risk Indicators](risk_indicators_g.md) - Grail-specific approaches
- [Design Document](DESIGN.md) - Technical architecture

## License

Internal tool for Dynatrace security assessments.

## Support

For issues or questions:
1. Check logs: `astra_phase1.log`
2. Enable debug mode: `--debug`
3. Review configuration: `config.yaml`

---

**Version:** 1.0.0 (MVP)  
**Last Updated:** January 22, 2026
