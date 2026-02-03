import { queryExecutionClient } from '@dynatrace-sdk/client-query';

/**
 * Executive Summary Tile
 * Displays: HRP v2.0 score, Risk Level, Total Vulnerabilities, Key Metrics
 * Uses Risk Concentration Model with automatic baseline calibration
 */

async function fetchTopologyScoreBlastScoreAge(tagfilter, tagkey, tagvalue, pgi_name, cve_flag, exclude_cve) {
  // Build CVE exclusion filter - only apply if cve_flag is ON
  const excludeCveStr = Array.isArray(exclude_cve) ? exclude_cve.join(',') : String(exclude_cve || '');
  let cveExclusionFilter = "";
  if (cve_flag === "ON" && excludeCveStr && excludeCveStr !== "NONE" && excludeCveStr.trim() !== "") {
    const cveList = excludeCveStr.split(',').map(c => c.trim()).filter(c => c.length > 0);
    const limitedCveList = cveList.slice(0, 50);
    if (limitedCveList.length > 0) {
      const cveChecks = limitedCveList.map(c => `in("${c}", vulnerability.references.cve)`).join(' or ');
      cveExclusionFilter = `| filter not(${cveChecks})`;
    }
  }
  
  const query = String.raw`fetch events
| filter event.kind=="SECURITY_EVENT"
| filter event.category=="VULNERABILITY_MANAGEMENT"
| filter event.provider=="Dynatrace"
| filter event.type=="VULNERABILITY_STATE_REPORT_EVENT"
| filter event.level=="ENTITY"
| filter vulnerability.resolution.status == "OPEN" and vulnerability.mute.status == "NOT_MUTED"
| dedup vulnerability.id, affected_entity.id
| sort timestamp desc
${cveExclusionFilter}
| expand pid=affected_entity.affected_processes.ids
| lookup [
  fetch dt.entity.process_group_instance
  | fieldsAdd tags, alias:pgi.tags
  | fields process_id=id, pgi.tags, process_name=entity.name, host_id=belongs_to[dt.entity.host]
  | filter matchesPhrase(process_name, "${pgi_name}") OR ("${pgi_name}"== "ALL")
  | lookup [ fetch dt.entity.host 
  | fieldsAdd host.tags=tags, monitoringMode
  ], sourceField:host_id, lookupField:id, fields:{host_name=entity.name, host.tags, monitoringMode=monitoringMode}
  ], sourceField: pid, lookupField:process_id, fields:{process_id,process_name, host_id, host_name,host.tags, pgi.tags, monitoringMode}
| filter ("${tagfilter}" == "ON" AND in(concat("${tagkey}", ":", "${tagvalue}"), pgi.tags)) OR (("${tagfilter}" == "ON" AND in(concat("${tagkey}", ":", "${tagvalue}"), host.tags))) OR ("${tagfilter}" == "OFF" AND isNotNull(vulnerability.id))
| dedup vulnerability.id, pid
| fieldsAdd has_exploit=if(vulnerability.davis_assessment.exploit_status=="AVAILABLE", 3.0, else:1.0)
| fieldsAdd has_cve=if(isNotNull(vulnerability.references.cve), 2.2, else:1.0)
| fieldsAdd vuln_contribution=vulnerability.davis_assessment.score * has_exploit * has_cve
| fieldsAdd age_duration = now() - vulnerability.parent.first_seen
| fieldsAdd age_days = age_duration / 1d
| fieldsAdd aging_score=if(age_days <= 30, 5.0,
    else:if(age_days <= 90, 15.0,
    else:if(age_days <= 180, 35.0,
    else:if(age_days <= 365, 60.0,
    else:if(age_days <= 730, 85.0,
    else:100.0)))))
| summarize 
total_vulnerabilities = countDistinct(vulnerability.id),
critical_vulns = countDistinct(if(vulnerability.risk.level=="CRITICAL", vulnerability.id)),
high_vulns = countDistinct(if(vulnerability.risk.level=="HIGH", vulnerability.id)),
medium_vulns = countDistinct(if(vulnerability.risk.level=="MEDIUM", vulnerability.id)),
low_vulns = countDistinct(if(vulnerability.risk.level=="LOW", vulnerability.id)),
exploit_available = countDistinct(if(vulnerability.davis_assessment.exploit_status=="AVAILABLE", vulnerability.id)),
vuln_sum=sum(vuln_contribution),
aging_score = avg(aging_score),
affected_pgis = countDistinct(pid),
total_related_entities = sum(related_entities.applications.count+related_entities.databases.count+related_entities.hosts.count+related_entities.services.count+related_entities.kubernetes_clusters.count+related_entities.kubernetes_workloads.count),
critical_related_entities = sum(related_entities.databases.count+related_entities.kubernetes_workloads.count+related_entities.services.count+related_entities.applications.count)
| fields total_vulnerabilities, critical_vulns, high_vulns, medium_vulns, low_vulns, exploit_available, vuln_sum, aging_score, affected_pgis, total_related_entities, critical_related_entities,
blast_score = 100* (1 - exp(-0.05 * total_related_entities)),
critical_path_score = if(total_related_entities > 0, (critical_related_entities * 100 )/total_related_entities)
| fieldsAdd topology_score = (0.70 * blast_score) + (0.30 * critical_path_score)`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000, maxResultRecords: 50000 }
  });
  
  return response.result.records ?? [];
}

async function fetchVulnLibraryRatio(tagfilter, tagkey, tagvalue, pgi_name) {
  const query = String.raw`fetch dt.entity.process_group_instance
| filter contains(entity.name, "${pgi_name}") OR ("${pgi_name}"== "ALL")
| fieldsAdd tags, alias:pgi.tags
| fieldsAdd host_id=belongs_to[dt.entity.host]
| lookup [ fetch dt.entity.host 
  | fieldsAdd host.tags=tags, monitoringMode
  ], sourceField:host_id, lookupField:id, fields:{host_name=entity.name, host.tags, monitoringMode=monitoringMode}
| filter ("${tagfilter}" == "ON" AND in(concat("${tagkey}", ":", "${tagvalue}"), pgi.tags)) OR (("${tagfilter}" == "ON" AND in(concat("${tagkey}", ":", "${tagvalue}"), host.tags))) OR ("${tagfilter}" == "OFF")
| expand dt.entity.software_component=contains[dt.entity.software_component]
| join [
  fetch dt.entity.software_component 
  | fields id, entity.name, packageName, softwareComponentShortName, softwareComponentVersion, softwareComponentType, softwareComponentFileName, softwareComponentFileHashes, lifetime], 
  on:left[dt.entity.software_component] == right[id], prefix:"sc."
| dedup {sc.id, id}
| lookup [ fetch events
  | filter event.provider == "Dynatrace"
  | filter event.type == "VULNERABILITY_STATE_REPORT_EVENT"
  | filter event.level == "ENTITY"
  | dedup vulnerability.id, affected_entity.vulnerable_component.id
  | summarize by:{affected_entity.vulnerable_component.id}, {total=count()}
  ], sourceField:sc.id, lookupField:affected_entity.vulnerable_component.id, fields:{total}
| fieldsAdd name=if(processType == "JAVA" and contains(sc.packageName, "#"), splitString(sc.packageName, "#")[0], else:sc.packageName)
| fields name, version=sc.softwareComponentVersion, total=if(isNotNull(total),total,else:0)
// CRITICAL FIX: Deduplicate by library name (ignoring version/PGI/host)
// This ensures each unique library is counted only once
| summarize by:{name}, {
    total_vulns=sum(total),
    versions=collectDistinct(version),
    version_count=countDistinct(version)
  }
| fieldsAdd total=total_vulns
| fields name, total, versions, version_count`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000 } 
  });

  return response.result.records ?? [];
}

// Fetch BASELINE vulnerability distribution (NO exclusions) - WITH CVE IDs
async function fetchBaselineVulnDistribution(tagfilter, tagkey, tagvalue, pgi_name) {
  const query = String.raw`fetch events
| filter event.kind=="SECURITY_EVENT"
| filter event.category=="VULNERABILITY_MANAGEMENT"
| filter event.provider=="Dynatrace"
| filter event.type=="VULNERABILITY_STATE_REPORT_EVENT"
| filter event.level=="ENTITY"
| filter vulnerability.resolution.status == "OPEN" and vulnerability.mute.status == "NOT_MUTED"
| dedup vulnerability.id, affected_entity.id
| sort timestamp desc
| expand pid=affected_entity.affected_processes.ids
| lookup [
  fetch dt.entity.process_group_instance
  | fieldsAdd tags, alias:pgi.tags
  | fields process_id=id, pgi.tags, process_name=entity.name, host_id=belongs_to[dt.entity.host]
  | filter matchesPhrase(process_name, "${pgi_name}") OR ("${pgi_name}"== "ALL")
  | lookup [ fetch dt.entity.host 
  | fieldsAdd host.tags=tags, monitoringMode
  ], sourceField:host_id, lookupField:id, fields:{host_name=entity.name, host.tags, monitoringMode=monitoringMode}
  ], sourceField: pid, lookupField:process_id, fields:{process_id,process_name, host_id, host_name,host.tags, pgi.tags, monitoringMode}
| filter ("${tagfilter}" == "ON" AND in(concat("${tagkey}", ":", "${tagvalue}"), pgi.tags)) OR (("${tagfilter}" == "ON" AND in(concat("${tagkey}", ":", "${tagvalue}"), host.tags))) OR ("${tagfilter}" == "OFF" AND isNotNull(vulnerability.id))
| dedup vulnerability.id, pid
| fieldsAdd has_exploit=if(vulnerability.davis_assessment.exploit_status=="AVAILABLE", 3.0, else:1.0)
| fieldsAdd has_cve=if(isNotNull(vulnerability.references.cve), 2.2, else:1.0)
| fieldsAdd vuln_contribution=vulnerability.davis_assessment.score * has_exploit * has_cve
| fields vuln_contribution, cve_id=vulnerability.references.cve, vuln_id=vulnerability.id, vuln_title=vulnerability.title
| sort vuln_contribution desc
| limit 500`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000, maxResultRecords: 500 }
  });
  
  return response.result.records ?? [];
}

// Fetch CURRENT vulnerability distribution (WITH exclusions if flag is ON) - WITH CVE IDs
async function fetchVulnDistribution(tagfilter, tagkey, tagvalue, pgi_name, cve_flag, exclude_cve) {
  const excludeCveStr = Array.isArray(exclude_cve) ? exclude_cve.join(',') : String(exclude_cve || '');
  let cveExclusionFilter = "";
  
  // Only apply exclusions if CVE flag is ON
  if (cve_flag === "ON" && excludeCveStr && excludeCveStr !== "NONE" && excludeCveStr.trim() !== "") {
    const cveList = excludeCveStr.split(',').map(c => c.trim()).filter(c => c.length > 0);
    
    // IMPORTANT: Don't limit CVEs - use all of them
    // If there are DQL issues, we'll handle them differently
    console.log(`CVE Exclusion Flag: ${cve_flag}`);
    console.log(`Total CVEs to exclude: ${cveList.length}`);
    
    if (cveList.length > 0) {
      // Split into chunks of 50 to avoid DQL complexity, apply multiple filters
      const chunkSize = 50;
      const chunks = [];
      for (let i = 0; i < cveList.length; i += chunkSize) {
        chunks.push(cveList.slice(i, i + chunkSize));
      }
      
      // Build multiple filter statements
      const filterStatements = chunks.map(chunk => {
        const cveChecks = chunk.map(c => `in("${c}", vulnerability.references.cve)`).join(' or ');
        return `not(${cveChecks})`;
      }).join(' and ');
      
      cveExclusionFilter = `| filter ${filterStatements}`;
      console.log(`Applied ${chunks.length} CVE filter chunks`);
    }
  } else {
    console.log(`CVE Exclusion Flag: ${cve_flag} - Exclusions NOT applied`);
  }

  const query = String.raw`fetch events
| filter event.kind=="SECURITY_EVENT"
| filter event.category=="VULNERABILITY_MANAGEMENT"
| filter event.provider=="Dynatrace"
| filter event.type=="VULNERABILITY_STATE_REPORT_EVENT"
| filter event.level=="ENTITY"
| filter vulnerability.resolution.status == "OPEN" and vulnerability.mute.status == "NOT_MUTED"
| dedup vulnerability.id, affected_entity.id
| sort timestamp desc
${cveExclusionFilter}
| expand pid=affected_entity.affected_processes.ids
| lookup [
  fetch dt.entity.process_group_instance
  | fieldsAdd tags, alias:pgi.tags
  | fields process_id=id, pgi.tags, process_name=entity.name, host_id=belongs_to[dt.entity.host]
  | filter matchesPhrase(process_name, "${pgi_name}") OR ("${pgi_name}"== "ALL")
  | lookup [ fetch dt.entity.host 
  | fieldsAdd host.tags=tags, monitoringMode
  ], sourceField:host_id, lookupField:id, fields:{host_name=entity.name, host.tags, monitoringMode=monitoringMode}
  ], sourceField: pid, lookupField:process_id, fields:{process_id,process_name, host_id, host_name,host.tags, pgi.tags, monitoringMode}
| filter ("${tagfilter}" == "ON" AND in(concat("${tagkey}", ":", "${tagvalue}"), pgi.tags)) OR (("${tagfilter}" == "ON" AND in(concat("${tagkey}", ":", "${tagvalue}"), host.tags))) OR ("${tagfilter}" == "OFF" AND isNotNull(vulnerability.id))
| dedup vulnerability.id, pid
| fieldsAdd has_exploit=if(vulnerability.davis_assessment.exploit_status=="AVAILABLE", 3.0, else:1.0)
| fieldsAdd has_cve=if(isNotNull(vulnerability.references.cve), 2.2, else:1.0)
| fieldsAdd vuln_contribution=vulnerability.davis_assessment.score * has_exploit * has_cve
| fields vuln_contribution, cve_id=vulnerability.references.cve, vuln_id=vulnerability.id, vuln_title=vulnerability.title
| sort vuln_contribution desc
| limit 500`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000, maxResultRecords: 500 }
  });
  
  return response.result.records ?? [];
}

// Calculate baseline metrics
function calculateBaselineMetrics(baselineDistribution) {
  const sortedContributions = baselineDistribution
    .map(v => Number(v.vuln_contribution) || 0)
    .filter(v => v > 0)
    .sort((a, b) => b - a);

  if (sortedContributions.length === 0) {
    return { baseline_sum: 0, baseline_top10_sum: 0, baseline_max: 0, vuln_count: 0 };
  }

  const baseline_sum = sortedContributions.reduce((sum, val) => sum + val, 0);
  const top10_count = Math.min(10, sortedContributions.length);
  const baseline_top10_sum = sortedContributions.slice(0, top10_count).reduce((sum, val) => sum + val, 0);
  const baseline_max = sortedContributions[0] || 0;

  return { 
    baseline_sum: Math.round(baseline_sum),
    baseline_top10_sum: Math.round(baseline_top10_sum),
    baseline_max: Math.round(baseline_max),
    vuln_count: sortedContributions.length
  };
}

// Calculate current metrics
function calculateCurrentMetrics(currentDistribution) {
  const sortedContributions = currentDistribution
    .map(v => Number(v.vuln_contribution) || 0)
    .filter(v => v > 0)
    .sort((a, b) => b - a);

  if (sortedContributions.length === 0) {
    return { current_sum: 0, current_top10_sum: 0, current_max: 0, current_count: 0 };
  }

  const current_sum = sortedContributions.reduce((sum, val) => sum + val, 0);
  const top10_count = Math.min(10, sortedContributions.length);
  const current_top10_sum = sortedContributions.slice(0, top10_count).reduce((sum, val) => sum + val, 0);
  const current_max = sortedContributions[0] || 0;

  return { 
    current_sum: Math.round(current_sum),
    current_top10_sum: Math.round(current_top10_sum),
    current_max: Math.round(current_max),
    current_count: sortedContributions.length
  };
}

// Risk Concentration Model
function calculateConcentrationScore(currentMetrics, baselineMetrics) {
  const { current_sum, current_top10_sum } = currentMetrics;
  const { baseline_sum, baseline_top10_sum } = baselineMetrics;

  if (baseline_sum === 0) {
    return { score: 0, band: "Zero", total_pct: 0, top10_pct: 0 };
  }

  const total_risk_pct = (current_sum / baseline_sum) * 100;
  const total_risk_score = Math.min(100, total_risk_pct);

  const top10_pct = baseline_top10_sum > 0 
    ? (current_top10_sum / baseline_top10_sum) * 100 
    : 0;
  const concentration_score = Math.min(100, top10_pct);

  const combined_score = (0.40 * total_risk_score) + (0.60 * concentration_score);

  let band = "";
  if (combined_score >= 90) band = "Critical";
  else if (combined_score >= 70) band = "High";
  else if (combined_score >= 50) band = "Medium";
  else if (combined_score >= 30) band = "Low";
  else if (combined_score > 0) band = "Minimal";
  else band = "Zero";

  return { 
    score: Math.round(combined_score * 100) / 100,
    band,
    total_pct: Math.round(total_risk_pct * 100) / 100,
    top10_pct: Math.round(top10_pct * 100) / 100
  };
}

export default async function () {
    // Step 1: Fetch BASELINE data (no exclusions)
    const baselineDistribution = await fetchBaselineVulnDistribution($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains);
    const baselineMetrics = calculateBaselineMetrics(baselineDistribution);

    // Step 2: Fetch CURRENT vulnerability distribution (with exclusions if CVE flag is ON)
    const currentDistribution = await fetchVulnDistribution($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains, $CVE_flag, $Exclude_CVE);
    const currentMetrics = calculateCurrentMetrics(currentDistribution);

    // DEBUG: Log metrics to diagnose score increase issue
    console.log("=== VULNERABILITY SCORING DEBUG ===");
    console.log("CVE Exclusion Flag:", $CVE_flag);
    console.log("Exclude CVE:", $Exclude_CVE);
    console.log("BASELINE:", baselineMetrics);
    console.log("CURRENT:", currentMetrics);
    console.log("Baseline records:", baselineDistribution.length);
    console.log("Current records:", currentDistribution.length);
    
    // Show top 10 from each WITH CVE IDs
    console.log("\n--- TOP 10 VULNERABILITIES (BASELINE) ---");
    baselineDistribution.slice(0, 10).forEach((v, i) => {
        console.log(`${i+1}. CVE: ${v.cve_id || 'N/A'} | Contribution: ${(Number(v.vuln_contribution) || 0).toFixed(2)} | Title: ${(v.vuln_title || '').substring(0, 50)}`);
    });
    
    console.log("\n--- TOP 10 VULNERABILITIES (CURRENT) ---");
    currentDistribution.slice(0, 10).forEach((v, i) => {
        console.log(`${i+1}. CVE: ${v.cve_id || 'N/A'} | Contribution: ${(Number(v.vuln_contribution) || 0).toFixed(2)} | Title: ${(v.vuln_title || '').substring(0, 50)}`);
    });
    
    const baselineTop10 = baselineDistribution.slice(0, 10).map(v => Number(v.vuln_contribution) || 0);
    const currentTop10 = currentDistribution.slice(0, 10).map(v => Number(v.vuln_contribution) || 0);
    console.log("\nBaseline Top 10 contributions:", baselineTop10);
    console.log("Current Top 10 contributions:", currentTop10);

    // Step 3: Fetch other HRP data
    const pgvulnsArray = await fetchTopologyScoreBlastScoreAge($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains, $CVE_flag, $Exclude_CVE);
    const libraryData = await fetchVulnLibraryRatio($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains);

    if (!pgvulnsArray || pgvulnsArray.length === 0) {
        return `## Executive Summary\n\n**No data available for the selected scope**`;
    }

    const data = pgvulnsArray[0];

    // Calculate HRP v2.0 components using CONCENTRATION MODEL
    const { score: s_vuln, total_pct, top10_pct } = calculateConcentrationScore(currentMetrics, baselineMetrics);
    
    console.log("Vulnerability Score:", s_vuln);
    console.log("Total Risk %:", total_pct);
    console.log("Top10 Concentration %:", top10_pct);
    console.log("=================================");

    const totalLib = libraryData.length;
    const vulnLib = libraryData.filter(lib => Number(lib.total) > 0).length;
    const vulnRatio = totalLib > 0 ? (vulnLib / totalLib) : 0;
    const s_supply = Math.min(100, 100 * Math.pow(vulnRatio, 0.7));

    const s_blast = Number(data.blast_score) || 0;
    const s_connectivity = Number(data.topology_score) || 0;
    const s_critical = Number(data.critical_path_score) || 0;
    const s_topo = Math.min(100, (0.40 * s_blast) + (0.35 * s_connectivity) + (0.25 * s_critical));

    const s_aging = Math.min(100, Number(data.aging_score) || 0);

    // Final HRP v2.0 Score with 2 decimal precision
    const overall_score = ($HRP_Vuln_Weight * s_vuln) + ($HRP_Supply_Weight * s_supply) + ($HRP_Topology_Weight * s_topo) + ($HRP_Aging_Weight * s_aging);
    const hrp_score = Math.min(Math.round(overall_score * 100) / 100, 100);

    // Determine risk level
    const risk_level = hrp_score > 75 ? "CRITICAL" : hrp_score > 50 ? "HIGH" : hrp_score > 25 ? "MEDIUM" : "LOW";
    const risk_emoji = hrp_score > 75 ? "🔴" : hrp_score > 50 ? "🟠" : hrp_score > 25 ? "🟡" : "🟢";

    // Generate timestamp
    const now = new Date();
    const timestamp = now.toISOString().replace('T', ' ').substring(0, 19);

    // Build markdown summary
    const summary = `
# 🔒 Security Risk Assessment - Executive Summary

**Assessment Date:** ${timestamp}  
**Scope:** ${$process_name_contains === "ALL" ? "All Process Groups" : $process_name_contains}

---

## 📊 Holistic Risk Posture (HRP v2.0)

### Overall Risk Score: **${hrp_score} / 100** ${risk_emoji}
**Risk Level:** **${risk_level}**

> This score represents the potential business impact from security exposure across your infrastructure, combining vulnerability severity, supply chain risk, topology exposure, and vulnerability aging.

---

## 🎯 Key Findings

### Vulnerability Overview
- **Total Vulnerabilities:** ${data.total_vulnerabilities || 0}
  - 🔴 Critical: ${data.critical_vulns || 0}
  - 🟠 High: ${data.high_vulns || 0}
  - 🟡 Medium: ${data.medium_vulns || 0}
  - 🟢 Low: ${data.low_vulns || 0}
- **Exploits Available:** ${data.exploit_available || 0} vulnerabilities have public exploits

### Infrastructure Impact
- **Affected Process Groups:** ${data.affected_pgis || 0}
- **Related Entities at Risk:** ${data.total_related_entities || 0}
- **Critical Infrastructure Affected:** ${data.critical_related_entities || 0} (databases, services, K8s)

### Supply Chain Risk
- **Total Libraries:** ${totalLib}
- **Vulnerable Libraries:** ${vulnLib}
- **Vulnerability Ratio:** ${(vulnRatio * 100).toFixed(1)}%

---

## 📈 Risk Component Breakdown

| Component | Score | Weight | Contribution |
|-----------|-------|--------|--------------|
| **Vulnerabilities** | ${s_vuln.toFixed(1)} | ${($HRP_Vuln_Weight * 100).toFixed(0)}% | ${($HRP_Vuln_Weight * s_vuln).toFixed(1)} |
| **Supply Chain** | ${s_supply.toFixed(1)} | ${($HRP_Supply_Weight * 100).toFixed(0)}% | ${($HRP_Supply_Weight * s_supply).toFixed(1)} |
| **Topology/Blast Radius** | ${s_topo.toFixed(1)} | ${($HRP_Topology_Weight * 100).toFixed(0)}% | ${($HRP_Topology_Weight * s_topo).toFixed(1)} |
| **Vulnerability Aging** | ${s_aging.toFixed(1)} | ${($HRP_Aging_Weight * 100).toFixed(0)}% | ${($HRP_Aging_Weight * s_aging).toFixed(1)} |

---

## 🎯 Recommendations

${hrp_score > 75 ? `
### ⚠️ **CRITICAL** - Immediate Action Required
1. Address all CRITICAL and HIGH severity vulnerabilities with available exploits
2. Review and patch vulnerable libraries in critical infrastructure paths
3. Implement network segmentation to reduce blast radius
4. Prioritize vulnerabilities older than 90 days
` : hrp_score > 50 ? `
### 🔶 **HIGH** - Urgent Attention Needed
1. Patch CRITICAL vulnerabilities within 7 days
2. Update vulnerable libraries with available patches
3. Monitor exploitation activity for HIGH severity vulnerabilities
4. Reduce supply chain risk by updating dependencies
` : hrp_score > 25 ? `
### 🟡 **MEDIUM** - Regular Maintenance Required
1. Continue patching HIGH and MEDIUM vulnerabilities
2. Monitor for new exploits
3. Keep libraries up to date
4. Regular security assessments recommended
` : `
### 🟢 **LOW** - Good Security Posture
1. Maintain current patching cadence
2. Continue monitoring for new vulnerabilities
3. Keep dependencies updated
4. Regular reviews recommended
`}

---

**Generated by ASTRA Risk Assessment Tool**  
*Powered by HRP v2.0 Risk Scoring Engine*
`;

    return summary;
}
