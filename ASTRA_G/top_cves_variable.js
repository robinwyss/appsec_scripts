import { queryExecutionClient } from '@dynatrace-sdk/client-query';

/**
 * Top CVEs Variable Populator
 * Returns top N CVEs by contribution score for use in $Exclude_CVE variable
 * Output format: Array of strings ["CVE-2024-21511", "CVE-2023-12345", ...]
 */

async function fetchTopCVEs(severity, tagfilter, tagkey, tagvalue, pgi_name, limit = 10) {
  const query = String.raw`fetch events
| filter event.kind=="SECURITY_EVENT"
| filter event.category=="VULNERABILITY_MANAGEMENT"
| filter event.provider=="Dynatrace"
| filter event.type=="VULNERABILITY_STATE_REPORT_EVENT"
| filter event.level=="ENTITY"
| filter vulnerability.resolution.status == "OPEN" and vulnerability.mute.status == "NOT_MUTED"
| filter isNotNull(vulnerability.references.cve)
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
| fields cve=vulnerability.references.cve, vuln_contribution, davis_score=vulnerability.davis_assessment.score
| sort vuln_contribution desc
| limit 500`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000, maxResultRecords: 500 }
  });
  
  return response.result.records ?? [];
}

export default async function () {
    const topVulns = await fetchTopCVEs($Severity, $Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains, 10);
    
    if (!topVulns || topVulns.length === 0) {
        return ["NONE"];
    }
    
    // Aggregate by CVE (in case same CVE appears on multiple PGIs)
    const cveMap = new Map();
    topVulns.forEach(v => {
        if (v.cve) {
            // Handle both string and array types
            const cve = Array.isArray(v.cve) ? v.cve[0] : String(v.cve);
            if (cve && cve.trim().length > 0) {
                const contrib = Number(v.vuln_contribution) || 0;
                if (cveMap.has(cve)) {
                    cveMap.set(cve, cveMap.get(cve) + contrib);
                } else {
                    cveMap.set(cve, contrib);
                }
            }
        }
    });
    
    if (cveMap.size === 0) {
        return ["NONE"];
    }
    
    // Sort by total contribution and get top 10
    const sortedCVEs = Array.from(cveMap.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([cve, contrib]) => cve);
    
    // Return as simple string array for dropdown variable
    return sortedCVEs.length > 0 ? sortedCVEs : ["NONE"];
}
