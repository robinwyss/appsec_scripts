import { queryExecutionClient } from '@dynatrace-sdk/client-query';

/**
 * HRP v2.0 Score Only - AUTOMATIC CALIBRATION VERSION v2
 * Automatically calculates worst_case_vuln and Dampening_Exponent from actual data
 * Score improves dynamically as vulnerabilities are resolved or excluded
 * 
 * Algorithm (FIXED - uses stable baseline):
 * 1. Fetch ALL vulnerabilities (no exclusions) to establish BASELINE parameters
 * 2. Calculate worst_case_vuln = 95th percentile from BASELINE distribution
 * 3. Calculate Dampening_Exponent from BASELINE concentration (0.5-0.9 range)
 * 4. Score CURRENT state (with exclusions) against BASELINE parameters
 * 5. Score improves as vulnerabilities are excluded/resolved (numerator drops, denominator fixed)
 */

async function fetchTopologyScoreBlastScoreAge(severity, tagfilter, tagkey, tagvalue, pgi_name, cve_flag, exclude_cve) {
  const severityValue = Array.isArray(severity) 
    ? severity.map(s => `"${s}"`).join(', ') 
    : `"${severity}"`;

  // Build CVE exclusion filter - only apply if flag is ON
  const excludeCveStr = Array.isArray(exclude_cve) ? exclude_cve.join(',') : String(exclude_cve || '');
  let cveExclusionFilter = "";
  
  // Only apply exclusions if CVE flag is ON
  if (cve_flag === "ON" && excludeCveStr && excludeCveStr !== "NONE" && excludeCveStr.trim() !== "") {
    const cveList = excludeCveStr.split(',').map(c => c.trim()).filter(c => c.length > 0);
    
    // Process ALL CVEs in chunks of 50
    const chunks = [];
    for (let i = 0; i < cveList.length; i += 50) {
      const chunk = cveList.slice(i, i + 50);
      const cveChecks = chunk.map(c => `in("${c}", vulnerability.references.cve)`).join(' or ');
      chunks.push(`not(${cveChecks})`);
    }
    
    if (chunks.length > 0) {
      cveExclusionFilter = `| filter ${chunks.join(' and ')}`;
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
vuln_sum=sum(vuln_contribution),
vuln_max=max(vuln_contribution),
vuln_avg=avg(vuln_contribution),
vuln_count=count(),
aging_score = avg(aging_score),
total_related_entities = sum(related_entities.applications.count+related_entities.databases.count+related_entities.hosts.count+related_entities.services.count+related_entities.kubernetes_clusters.count+related_entities.kubernetes_workloads.count),
critical_related_entities = sum(related_entities.databases.count+related_entities.kubernetes_workloads.count+related_entities.services.count+related_entities.applications.count)
| fields vuln_sum, vuln_max, vuln_avg, vuln_count, aging_score, total_related_entities, critical_related_entities,
blast_score = 100* (1 - exp(-0.05 * total_related_entities)),
critical_path_score = if(total_related_entities > 0, (critical_related_entities * 100 )/total_related_entities)
| fieldsAdd topology_score = (0.70 * blast_score) + (0.30 * critical_path_score)`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000, maxResultRecords: 50000 }
  });
  
  return response.result.records ?? [];
}

// NEW: Fetch BASELINE vulnerability distribution (NO exclusions - for calibration)
async function fetchBaselineVulnDistribution(severity, tagfilter, tagkey, tagvalue, pgi_name) {
  const severityValue = Array.isArray(severity) 
    ? severity.map(s => `"${s}"`).join(', ') 
    : `"${severity}"`;

  // NO CVE exclusion filter - this is the baseline
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
| fields vuln_contribution
| sort vuln_contribution desc
| limit 500`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000, maxResultRecords: 500 }
  });
  
  return response.result.records ?? [];
}

// Fetch CURRENT vulnerability distribution (WITH exclusions if flag is ON - for scoring)
async function fetchVulnDistribution(severity, tagfilter, tagkey, tagvalue, pgi_name, cve_flag, exclude_cve) {
  const severityValue = Array.isArray(severity) 
    ? severity.map(s => `"${s}"`).join(', ') 
    : `"${severity}"`;

  const excludeCveStr = Array.isArray(exclude_cve) ? exclude_cve.join(',') : String(exclude_cve || '');
  let cveExclusionFilter = "";
  
  // Only apply exclusions if CVE flag is ON
  if (cve_flag === "ON" && excludeCveStr && excludeCveStr !== "NONE" && excludeCveStr.trim() !== "") {
    const cveList = excludeCveStr.split(',').map(c => c.trim()).filter(c => c.length > 0);
    
    // Process ALL CVEs in chunks of 50
    const chunks = [];
    for (let i = 0; i < cveList.length; i += 50) {
      const chunk = cveList.slice(i, i + 50);
      const cveChecks = chunk.map(c => `in("${c}", vulnerability.references.cve)`).join(' or ');
      chunks.push(`not(${cveChecks})`);
    }
    
    if (chunks.length > 0) {
      cveExclusionFilter = `| filter ${chunks.join(' and ')}`;
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
| fields vuln_contribution
| sort vuln_contribution desc
| limit 500`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000, maxResultRecords: 500 }
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

// Calculate baseline metrics - total risk and top vulnerability concentration
function calculateBaselineMetrics(baselineDistribution) {
  const sortedContributions = baselineDistribution
    .map(v => Number(v.vuln_contribution) || 0)
    .filter(v => v > 0)
    .sort((a, b) => b - a); // Sort descending for top-N calculations

  if (sortedContributions.length === 0) {
    return { 
      baseline_sum: 0, 
      baseline_top10_sum: 0,
      baseline_max: 0,
      vuln_count: 0 
    };
  }

  const baseline_sum = sortedContributions.reduce((sum, val) => sum + val, 0);
  
  // Calculate top 10 vulnerability sum (or fewer if less than 10 vulns)
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

// Calculate current metrics from vulnerability data
function calculateCurrentMetrics(currentDistribution) {
  const sortedContributions = currentDistribution
    .map(v => Number(v.vuln_contribution) || 0)
    .filter(v => v > 0)
    .sort((a, b) => b - a);

  if (sortedContributions.length === 0) {
    return { 
      current_sum: 0, 
      current_top10_sum: 0,
      current_max: 0,
      current_count: 0 
    };
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

// Risk Concentration Model: combines total risk + top vulnerability concentration
function calculateConcentrationScore(currentMetrics, baselineMetrics) {
  const { current_sum, current_top10_sum } = currentMetrics;
  const { baseline_sum, baseline_top10_sum } = baselineMetrics;

  if (baseline_sum === 0) {
    return { score: 0, band: "Zero", total_pct: 0, top10_pct: 0 };
  }

  // Component 1: Total risk as percentage of baseline (0-100)
  const total_risk_pct = (current_sum / baseline_sum) * 100;
  const total_risk_score = Math.min(100, total_risk_pct);

  // Component 2: Top 10 concentration as percentage of baseline top 10 (0-100)
  const top10_pct = baseline_top10_sum > 0 
    ? (current_top10_sum / baseline_top10_sum) * 100 
    : 0;
  const concentration_score = Math.min(100, top10_pct);

  // Combined score: 40% total risk + 60% top-10 concentration
  // This makes the score MORE sensitive to removing top vulnerabilities
  const combined_score = (0.40 * total_risk_score) + (0.60 * concentration_score);

  // Determine risk band
  let band = "";
  if (combined_score >= 90) {
    band = "Critical";
  } else if (combined_score >= 70) {
    band = "High";
  } else if (combined_score >= 50) {
    band = "Medium";
  } else if (combined_score >= 30) {
    band = "Low";
  } else if (combined_score > 0) {
    band = "Minimal";
  } else {
    band = "Zero";
  }

  return { 
    score: Math.round(combined_score * 100) / 100,  // Two decimal precision
    band,
    total_pct: Math.round(total_risk_pct * 100) / 100,
    top10_pct: Math.round(top10_pct * 100) / 100
  };
}

export default async function () {
    // Step 1: Fetch BASELINE data (no exclusions) for calibration
    const baselineDistribution = await fetchBaselineVulnDistribution($Severity, $Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains);
    
    // Step 2: Calculate baseline metrics (total risk + top 10 concentration)
    const baselineMetrics = calculateBaselineMetrics(baselineDistribution);

    // Step 3: Fetch CURRENT vulnerability distribution (with exclusions if flag is ON)
    const currentDistribution = await fetchVulnDistribution($Severity, $Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains, $CVE_flag, $Exclude_CVE);
    
    // Step 4: Calculate current metrics from distribution
    const currentMetrics = calculateCurrentMetrics(currentDistribution);

    // Step 5: Fetch other HRP data (topology, library, aging)
    const pgvulnsArray = await fetchTopologyScoreBlastScoreAge($Severity, $Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains, $CVE_flag, $Exclude_CVE);
    const libraryData = await fetchVulnLibraryRatio($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains);

    if (!pgvulnsArray || pgvulnsArray.length === 0) {
        return [{ value: 0, label: "No Data" }];
    }

    const data = pgvulnsArray[0];

    // Calculate improvement percentage (total risk reduction)
    const improvement_pct = baselineMetrics.baseline_sum > 0 
      ? Math.round(((baselineMetrics.baseline_sum - currentMetrics.current_sum) / baselineMetrics.baseline_sum) * 10000) / 100 
      : 0;

    // Calculate HRP v2.0 components using CONCENTRATION MODEL
    const { score: s_vuln_base, band, total_pct, top10_pct } = calculateConcentrationScore(currentMetrics, baselineMetrics);
    const s_vuln = s_vuln_base;

    // DEBUG: Print baseline and current metrics
    console.log("=== DEBUG: Vulnerability Metrics ===");
    console.log("BASELINE:", JSON.stringify(baselineMetrics, null, 2));
    console.log("CURRENT:", JSON.stringify(currentMetrics, null, 2));
    console.log("PERCENTAGES - Total:", total_pct, "% | Top10:", top10_pct, "%");
    console.log("VULN SCORE:", s_vuln, "| Band:", band);

    const totalLib = libraryData.length;
    const vulnLib = libraryData.filter(lib => Number(lib.total) > 0).length;
    const vulnRatio = totalLib > 0 ? (vulnLib / totalLib) : 0;
    const s_supply = Math.min(100, 100 * Math.pow(vulnRatio, 0.7));

    const s_blast = Number(data.blast_score) || 0;
    const s_connectivity = Number(data.topology_score) || 0;
    const s_critical = Number(data.critical_path_score) || 0;
    const s_topo = Math.min(100, (0.40 * s_blast) + (0.35 * s_connectivity) + (0.25 * s_critical));

    const s_aging = Math.min(100, Number(data.aging_score) || 0);

    // Final HRP v2.0 Score with configurable weights
    const overall_score = ($HRP_Vuln_Weight * s_vuln) + ($HRP_Supply_Weight * s_supply) + ($HRP_Topology_Weight * s_topo) + ($HRP_Aging_Weight * s_aging);
    const hrp_score = Math.min(Math.round(overall_score * 100) / 100, 100);

    // DEBUG: Print component scores and weights
    console.log("=== DEBUG: Component Scores ===");
    console.log("s_vuln:", s_vuln, "| Weight:", $HRP_Vuln_Weight, "| Contribution:", $HRP_Vuln_Weight * s_vuln);
    console.log("s_supply:", s_supply, "| Weight:", $HRP_Supply_Weight, "| Contribution:", $HRP_Supply_Weight * s_supply);
    console.log("s_topo:", s_topo, "| Weight:", $HRP_Topology_Weight, "| Contribution:", $HRP_Topology_Weight * s_topo);
    console.log("s_aging:", s_aging, "| Weight:", $HRP_Aging_Weight, "| Contribution:", $HRP_Aging_Weight * s_aging);
    console.log("OVERALL SCORE:", overall_score, "| FINAL HRP:", hrp_score);
    console.log("====================================");

    // Return value with detailed component breakdown for debugging
    const improvement_indicator = improvement_pct > 0 ? `${improvement_pct}% ↓` : `${Math.abs(improvement_pct)}% ↑`;
    return [
        {
            value: hrp_score,
            label: `HRP v2.0 (${improvement_indicator} | V:${s_vuln.toFixed(2)} T:${s_topo.toFixed(2)} S:${s_supply.toFixed(2)} A:${s_aging.toFixed(2)} | Top10:${top10_pct}%)`
        }
    ];
}
