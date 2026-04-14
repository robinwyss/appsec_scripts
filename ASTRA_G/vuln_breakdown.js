    import { queryExecutionClient } from '@dynatrace-sdk/client-query';

    /**
     * Top 10 Vulnerabilities Breakdown Tile
     * Displays: Top 10 most critical vulnerabilities with details
     * Replaces Process Group breakdown from PDF with vulnerability-focused view
     */

    async function fetchTop10Vulnerabilities(tagfilter, tagkey, tagvalue, pgi_name, cve_flag, exclude_cve) {
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
    | fields 
    vuln_id=vulnerability.id,
    vuln_display_id=vulnerability.display.id,
    vuln_title=vulnerability.title,
    severity=vulnerability.risk.level,
    davis_score=vulnerability.davis_assessment.score,
    has_exploit=vulnerability.davis_assessment.exploit_status,
    exposure=vulnerability.davis_assessment.exposure,
    cvss_score=vulnerability.cvss.score,
    cve_id=vulnerability.references.cve,
    affected_component=affected_entity.vulnerable_component.name,
    component_version=affected_entity.vulnerable_component.version,
    vuln_contribution,
    age_days,
    related_services=related_entities.services.count,
    related_databases=related_entities.databases.count,
    related_hosts=related_entities.hosts.count,
    total_related=related_entities.applications.count+related_entities.databases.count+related_entities.hosts.count+related_entities.services.count+related_entities.kubernetes_clusters.count+related_entities.kubernetes_workloads.count,
    process_name
    | sort vuln_contribution desc
    | limit 10`;

    const response = await queryExecutionClient.queryExecute({ 
        body: { query, requestTimeoutMilliseconds: 60000, maxResultRecords: 10 }
    });
    
    return response.result.records ?? [];
    }

    export default async function () {
        // Fetch top 10 vulnerabilities (with exclusions if flag is ON)
        const vulnData = await fetchTop10Vulnerabilities($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains, $CVE_flag, $Exclude_CVE);

        if (!vulnData || vulnData.length === 0) {
            return [];
        }

        // Format data for table display
        return vulnData.map((vuln, index) => {
            const risk_score = parseFloat((Number(vuln.vuln_contribution) || 0).toFixed(1));
            const age = Math.round(Number(vuln.age_days) || 0);
            const exploit_status = vuln.has_exploit === "AVAILABLE" ? "⚠️ YES" : "No";
            const exposure_icon = vuln.exposure === "PUBLIC_NETWORK" ? "🌐" : "🔒";
            const vuln_id = vuln.vuln_display_id || vuln.vuln_id;
            
            return {
                rank: index + 1,
                vulnerability_id: vuln_id,
                vulnerability_url: $Environment_url + `ui/apps/dynatrace.security.vulnerabilities/vulnerabilities/${vuln_id}?from=now-24h&to=now`,
                title: vuln.vuln_title || "Unknown",
                severity: vuln.severity || "UNKNOWN",
                risk_score: risk_score,
                davis_score: parseFloat((Number(vuln.davis_score) || 0).toFixed(1)),
                has_exploit: exploit_status,
                age_days: age,
                affected_component: vuln.affected_component || "Unknown",
                cve_id: vuln.cve_id || "N/A",
                blast_radius: Number(vuln.total_related) || 0,
                related_services: Number(vuln.related_services) || 0,
                related_databases: Number(vuln.related_databases) || 0,
                related_hosts: Number(vuln.related_hosts) || 0,
                process_group: vuln.process_name || "Unknown"
            };
        });
    }
