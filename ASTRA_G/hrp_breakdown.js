import { queryExecutionClient } from '@dynatrace-sdk/client-query';

/**
 * HRP v2.0 Component Breakdown Tile
 * Displays: Detailed breakdown of the 4 HRP components with scores
 * Uses Risk Concentration Model with automatic baseline calibration
 */

async function fetchTopologyScoreBlastScoreAge(tagfilter, tagkey, tagvalue, pgi_name, cve_flag, exclude_cve) {
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
total_vulnerabilities = countDistinct(vulnerability.id),
vuln_sum=sum(vuln_contribution),
aging_score = avg(aging_score),
avg_age_days = avg(age_days),
total_related_entities = sum(related_entities.applications.count+related_entities.databases.count+related_entities.hosts.count+related_entities.services.count+related_entities.kubernetes_clusters.count+related_entities.kubernetes_workloads.count),
critical_related_entities = sum(related_entities.databases.count+related_entities.kubernetes_workloads.count+related_entities.services.count+related_entities.applications.count)
| fields total_vulnerabilities, vuln_sum, aging_score, avg_age_days, total_related_entities, critical_related_entities,
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

// Fetch BASELINE vulnerability distribution (NO exclusions)
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
| fields vuln_contribution
| sort vuln_contribution desc
| limit 500`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000, maxResultRecords: 500 }
  });
  
  return response.result.records ?? [];
}

// Fetch CURRENT vulnerability distribution (WITH exclusions if flag is ON)
async function fetchVulnDistribution(tagfilter, tagkey, tagvalue, pgi_name, cve_flag, exclude_cve) {
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

    // Step 2: Fetch CURRENT vulnerability distribution (with exclusions if flag is ON)
    const currentDistribution = await fetchVulnDistribution($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains, $CVE_flag, $Exclude_CVE);
    const currentMetrics = calculateCurrentMetrics(currentDistribution);

    // Step 3: Fetch other HRP data
    const pgvulnsArray = await fetchTopologyScoreBlastScoreAge($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains, $CVE_flag, $Exclude_CVE);
    const libraryData = await fetchVulnLibraryRatio($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains);

    if (!pgvulnsArray || pgvulnsArray.length === 0) {
        return [];
    }

    const data = pgvulnsArray[0];

    // Calculate HRP v2.0 components using CONCENTRATION MODEL
    const { score: s_vuln } = calculateConcentrationScore(currentMetrics, baselineMetrics);

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

    // Calculate contribution ratios (percentage of overall score from each component)
    const vuln_contribution = $HRP_Vuln_Weight * s_vuln;
    const supply_contribution = $HRP_Supply_Weight * s_supply;
    const topo_contribution = $HRP_Topology_Weight * s_topo;
    const aging_contribution = $HRP_Aging_Weight * s_aging;
    
    // Return breakdown data for visualization
    return [
        {
            component: "Vulnerability Score",
            contribution_ratio: parseFloat(((vuln_contribution / overall_score) * 100).toFixed(1)),
            // raw_score: parseFloat(s_vuln.toFixed(2)),
            // weight: 60,
            // contribution: parseFloat(vuln_contribution.toFixed(2)),
            // details: `${data.total_vulnerabilities || 0} vulnerabilities with weighted severity (exploit factor × CVE factor × Davis score)`,
            // formula: "100 × √(Σ contributions) / √500 (sqrt dampening)"
        },
        {
            component: "Supply Chain Risk",
            contribution_ratio: parseFloat(((supply_contribution / overall_score) * 100).toFixed(1)),
            // raw_score: parseFloat(s_supply.toFixed(2)),
            // weight: 20,
            // contribution: parseFloat(supply_contribution.toFixed(2)),
            // details: `${vulnLib}/${totalLib} libraries vulnerable (${(vulnRatio * 100).toFixed(1)}% ratio)`,
            // formula: "100 × (vulnerable_ratio)^0.7"
        },
        {
            component: "Topology/Blast Radius",
            contribution_ratio: parseFloat(((topo_contribution / overall_score) * 100).toFixed(1)),
            // raw_score: parseFloat(s_topo.toFixed(2)),
            // weight: 15,
            // contribution: parseFloat(topo_contribution.toFixed(2)),
            // details: `${data.total_related_entities || 0} related entities, ${data.critical_related_entities || 0} critical`,
            // formula: "0.4×blast + 0.35×connectivity + 0.25×critical_path",
            // sub_scores: {
            //     blast: parseFloat(s_blast.toFixed(2)),
            //     connectivity: parseFloat(s_connectivity.toFixed(2)),
            //     critical_path: parseFloat(s_critical.toFixed(2))
            // }
        },
        {
            component: "Vulnerability Aging",
            contribution_ratio: parseFloat(((aging_contribution / overall_score) * 100).toFixed(1)),
            // raw_score: parseFloat(s_aging.toFixed(2)),
            // weight: 5,
            // contribution: parseFloat(aging_contribution.toFixed(2)),
            // details: `Average age: ${(Number(data.avg_age_days) || 0).toFixed(0)} days`,
            // formula: "Avg[(age_days/365) × severity_weight] × 0.7"
        },
        {
            component: "MAX HRP v2.0",
            contribution_ratio: 100.0,
            // raw_score: hrp_score,
            // weight: 100,
            // contribution: hrp_score,
            // details: "Combined risk score",
            // formula: "0.60×Vuln + 0.20×Supply + 0.15×Topo + 0.05×Aging"
        }
    ];
}
