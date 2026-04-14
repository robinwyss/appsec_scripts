import { queryExecutionClient } from '@dynatrace-sdk/client-query';

/**
 * Vulnerability Distribution Tile
 * Displays: Bar chart of vulnerability counts by severity level
 * Shows distribution after CVE exclusions applied
 */

async function fetchVulnerabilityDistribution(tagfilter, tagkey, tagvalue, pgi_name, cve_flag, exclude_cve) {
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
| summarize 
total = countDistinct(vulnerability.id),
critical = countDistinct(if(vulnerability.risk.level=="CRITICAL", vulnerability.id)),
high = countDistinct(if(vulnerability.risk.level=="HIGH", vulnerability.id)),
medium = countDistinct(if(vulnerability.risk.level=="MEDIUM", vulnerability.id)),
low = countDistinct(if(vulnerability.risk.level=="LOW", vulnerability.id)),
none = countDistinct(if(vulnerability.risk.level=="NONE", vulnerability.id))`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000, maxResultRecords: 50000 }
  });
  
  return response.result.records ?? [];
}

export default async function () {
    // Fetch vulnerability distribution (with CVE exclusions if flag is ON)
    const distData = await fetchVulnerabilityDistribution($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains, $CVE_flag, $Exclude_CVE);

    if (!distData || distData.length === 0) {
        return [];
    }

    const data = distData[0];

    // Prepare data for bar chart visualization - severity only
    // Format: [{severity, count, percentage}]
    return [
        {
            severity: "CRITICAL",
            count: Number(data.critical) || 0,
            percentage: data.total > 0 ? ((Number(data.critical) || 0) / data.total * 100).toFixed(1) : 0
        },
        {
            severity: "HIGH",
            count: Number(data.high) || 0,
            percentage: data.total > 0 ? ((Number(data.high) || 0) / data.total * 100).toFixed(1) : 0
        },
        {
            severity: "MEDIUM",
            count: Number(data.medium) || 0,
            percentage: data.total > 0 ? ((Number(data.medium) || 0) / data.total * 100).toFixed(1) : 0
        },
        {
            severity: "LOW",
            count: Number(data.low) || 0,
            percentage: data.total > 0 ? ((Number(data.low) || 0) / data.total * 100).toFixed(1) : 0
        },
        {
            severity: "NONE",
            count: Number(data.none) || 0,
            percentage: data.total > 0 ? ((Number(data.none) || 0) / data.total * 100).toFixed(1) : 0
        }
    ];
}
