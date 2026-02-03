# HRPv2 - Holistic Risk Posture Dashboard
## POTENTIAL BUSINESS IMPACT

**Filters Active:** Tag Filter = $Tag_Filter | PGI = $process_name_contains | Tag = $Tag_Key:$Tag_Value | Severity = $Severity

**HRP Weights:** Vulnerability= $HRP_Vuln_Weight  | Supply Chain= $HRP_Supply_Weight | Topology= $HRP_Topology_Weight | Aging= $HRP_Aging_Weight

**CVE Exclusion:** $CVE_flag ($Exclude_CVE)

---

### What is HRPv2?
HRP v2.0 measures **Potential Business Impact from Security Exposure** by quantifying:
- **% Vulnerabilities**: How easy to exploit? (CVE IDs, public exploits, high severity)
- **% Supply Chain**: How widespread is the weakness? (% of vulnerable libraries)
- **% Topology**: How much damage if breached? (blast radius, interconnectivity)
- **% Aging**: How long have we been exposed? (time since first detection)

**Scale:** 0-100 (0=No Risk, 100=Critical Risk)

### Prioritization Mechanism
Uses **Risk Concentration Model** with 60% weight on top-10 vulnerabilities. Removing critical CVEs causes dramatic score drops, enabling data-driven remediation prioritization. Toggle `$CVE_flag` to model "what-if" scenarios.

---

📚 **Full Documentation:** See [ASTRA_ON_GRAIL.md](ASTRA_ON_GRAIL.md) for algorithm details, business risk assessment, and tile documentation.
