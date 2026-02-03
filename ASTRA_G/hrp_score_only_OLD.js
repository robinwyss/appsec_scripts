import { queryExecutionClient } from '@dynatrace-sdk/client-query';

/**
 * HRP v2.0 Score Only - Main Risk Score Display
 * Displays single value: overall HRP v2.0 score (0-100)
 * Matches PDF: Main score box in Executive Summary
 */

async function fetchTopologyScoreBlastScoreAge(severity, tagfilter, tagkey, tagvalue, pgi_name, exclude_cve) {
  const severityValue = Array.isArray(severity) 
    ? severity.map(s => `"${s}"`).join(', ') 
    : `"${severity}"`;

  // Build CVE exclusion filter - limit to 50 CVEs to avoid DQL complexity limits
  const excludeCveStr = Array.isArray(exclude_cve) ? exclude_cve.join(',') : String(exclude_cve || '');
  let cveExclusionFilter = "";
  if (excludeCveStr && excludeCveStr !== "NONE" && excludeCveStr.trim() !== "") {
    const cveList = excludeCveStr.split(',').map(c => c.trim()).filter(c => c.length > 0);
    // Limit to first 50 CVEs to prevent "EXPRESSION_TOO_DEEPLY_NESTED" error
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
vuln_sum=sum(vuln_contribution),
aging_score = avg(aging_score),
total_related_entities = sum(related_entities.applications.count+related_entities.databases.count+related_entities.hosts.count+related_entities.services.count+related_entities.kubernetes_clusters.count+related_entities.kubernetes_workloads.count),
critical_related_entities = sum(related_entities.databases.count+related_entities.kubernetes_workloads.count+related_entities.services.count+related_entities.applications.count)
| fields vuln_sum, aging_score, total_related_entities, critical_related_entities,
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
| fieldsAdd name=if(processType == "JAVA" and  contains(sc.packageName, "#"), splitString(sc.packageName, "#")[0], else:sc.packageName)
| fields name, version=sc.softwareComponentVersion, total=if(isNotNull(total),total,else:0)`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000 } 
  });

  return response.result.records ?? [];
}

export default async function () {
    // Fetch data
    const pgvulnsArray = await fetchTopologyScoreBlastScoreAge($Severity, $Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains, $Exclude_CVE);
    const libraryData = await fetchVulnLibraryRatio($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains);

    if (!pgvulnsArray || pgvulnsArray.length === 0) {
        return [{ value: 0, label: "No Data" }];
    }

    const data = pgvulnsArray[0];

    // Calculate HRP v2.0 components
    const rawVulnSum = Number(data.vuln_sum) || 0;
    const s_vuln_base = Math.min(100, 100 * (Math.pow(rawVulnSum, $Dampening_Exponent) / Math.pow($worst_case_vuln, $Dampening_Exponent)));
    const s_vuln = Math.pow(s_vuln_base / 100, 0.75) * 100; // Additional hardcoded dampening for vulnerability score

    const totalLib = libraryData.length;
    const vulnLib = libraryData.filter(lib => Number(lib.total) > 0).length;
    const vulnRatio = totalLib > 0 ? (vulnLib / totalLib) : 0;
    const s_supply = Math.min(100, 100 * Math.pow(vulnRatio, 0.7));

    const s_blast = Number(data.blast_score) || 0;
    const s_connectivity = Number(data.topology_score) || 0;
    const s_critical = Number(data.critical_path_score) || 0;
    const s_topo = Math.min(100, (0.40 * s_blast) + (0.35 * s_connectivity) + (0.25 * s_critical));

    const s_aging = Math.min(100, Number(data.aging_score) || 0);

    // Final HRP v2.0 Score
    const overall_score = ($HRP_Vuln_Weight * s_vuln) + ($HRP_Supply_Weight * s_supply) + ($HRP_Topology_Weight * s_topo) + ($HRP_Aging_Weight * s_aging);
    const hrp_score = Math.min(Math.round(overall_score), 100);

    // Return single value for score tile
    return [
        {
            value: hrp_score,
            label: "HRP v2.0 Score"
        }
    ];
}
