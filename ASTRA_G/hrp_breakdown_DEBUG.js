import { queryExecutionClient } from '@dynatrace-sdk/client-query';

/**
 * DEBUG VERSION - HRP v2.0 Component Breakdown Tile
 * Outputs detailed diagnostic information for troubleshooting
 */

async function fetchTopologyScoreBlastScoreAge(tagfilter, tagkey, tagvalue, pgi_name) {
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
| fieldsAdd age_duration = now() - vulnerability.parent.first_seen
| fieldsAdd age_days = age_duration / 1d
| fieldsAdd aging_score=if(age_days > 0, (age_days / 365) * 20, else:0)
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
| fieldsAdd name=if(processType == "JAVA" and  contains(sc.packageName, "#"), splitString(sc.packageName, "#")[0], else:sc.packageName)
| fields name, version=sc.softwareComponentVersion, total=if(isNotNull(total),total,else:0)`;

  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000 } 
  });

  return response.result.records ?? [];
}

export default async function () {
    // Fetch data
    const pgvulnsArray = await fetchTopologyScoreBlastScoreAge($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains);
    const libraryData = await fetchVulnLibraryRatio($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains);

    const debugOutput = {
        timestamp: new Date().toISOString(),
        input_variables: {
            Tag_Filter: $Tag_Filter,
            Tag_Key: $Tag_Key,
            Tag_Value: $Tag_Value,
            process_name_contains: $process_name_contains,
            HRP_Vuln_Weight: $HRP_Vuln_Weight,
            HRP_Supply_Weight: $HRP_Supply_Weight,
            HRP_Topology_Weight: $HRP_Topology_Weight,
            HRP_Aging_Weight: $HRP_Aging_Weight,
            Dampening_Exponent: $Dampening_Exponent,
            worst_case_vuln: $worst_case_vuln
        },
        raw_query_results: {
            vulnerability_query: {
                records_returned: pgvulnsArray ? pgvulnsArray.length : 0,
                data: pgvulnsArray ? pgvulnsArray[0] : null
            },
            library_query: {
                total_libraries: libraryData ? libraryData.length : 0,
                sample_libraries: libraryData ? libraryData.slice(0, 5) : [],
                vulnerable_libraries: libraryData ? libraryData.filter(lib => Number(lib.total) > 0).length : 0
            }
        }
    };

    if (!pgvulnsArray || pgvulnsArray.length === 0) {
        debugOutput.error = "No vulnerability data returned from query";
        debugOutput.suggestion = "Check that vulnerabilities exist for the selected scope and that filters are correct";
        return [debugOutput];
    }

    const data = pgvulnsArray[0];

    // ===== VULNERABILITY COMPONENT =====
    const rawVulnSum = Number(data.vuln_sum) || 0;
    const vuln_dampened = Math.pow(rawVulnSum, $Dampening_Exponent);
    const vuln_max_dampened = Math.pow($worst_case_vuln, $Dampening_Exponent);
    const s_vuln = 100 * (vuln_dampened / vuln_max_dampened);

    debugOutput.vulnerability_component = {
        raw_vuln_sum: rawVulnSum,
        dampening_exponent: $Dampening_Exponent,
        worst_case_vuln: $worst_case_vuln,
        vuln_dampened: vuln_dampened,
        vuln_max_dampened: vuln_max_dampened,
        s_vuln_score: s_vuln,
        weight: $HRP_Vuln_Weight,
        weighted_contribution: $HRP_Vuln_Weight * s_vuln,
        total_vulnerabilities: data.total_vulnerabilities
    };

    // ===== SUPPLY CHAIN COMPONENT =====
    const totalLib = libraryData.length;
    const vulnLib = libraryData.filter(lib => Number(lib.total) > 0).length;
    const vulnRatio = totalLib > 0 ? (vulnLib / totalLib) : 0;
    const s_supply = 100 * Math.pow(vulnRatio, 0.7);

    debugOutput.supply_chain_component = {
        total_libraries: totalLib,
        vulnerable_libraries: vulnLib,
        vulnerability_ratio: vulnRatio,
        ratio_dampened_0_7: Math.pow(vulnRatio, 0.7),
        s_supply_score: s_supply,
        weight: $HRP_Supply_Weight,
        weighted_contribution: $HRP_Supply_Weight * s_supply,
        issue_detected: totalLib === 0 ? "NO_LIBRARIES_FOUND" : vulnLib === 0 ? "NO_VULNERABLE_LIBRARIES" : null
    };

    // ===== TOPOLOGY COMPONENT =====
    const s_blast = Number(data.blast_score) || 0;
    const s_connectivity = Number(data.topology_score) || 0;
    const s_critical = Number(data.critical_path_score) || 0;
    const s_topo = (0.40 * s_blast) + (0.35 * s_connectivity) + (0.25 * s_critical);

    debugOutput.topology_component = {
        raw_data: {
            total_related_entities: data.total_related_entities,
            critical_related_entities: data.critical_related_entities
        },
        blast_radius_score: s_blast,
        connectivity_score: s_connectivity,
        critical_path_score: s_critical,
        formula: "0.40 × blast + 0.35 × connectivity + 0.25 × critical",
        s_topo_score: s_topo,
        weight: $HRP_Topology_Weight,
        weighted_contribution: $HRP_Topology_Weight * s_topo,
        issue_detected: data.total_related_entities === 0 ? "NO_RELATED_ENTITIES" : null
    };

    // ===== AGING COMPONENT =====
    const raw_aging_score = Number(data.aging_score) || 0;
    const s_aging = raw_aging_score * 0.7;

    debugOutput.aging_component = {
        raw_aging_score: raw_aging_score,
        avg_age_days: data.avg_age_days,
        aging_multiplier: 0.7,
        s_aging_score: s_aging,
        weight: $HRP_Aging_Weight,
        weighted_contribution: $HRP_Aging_Weight * s_aging,
        issue_detected: raw_aging_score === 0 ? "NO_AGING_DATA" : null
    };

    // ===== FINAL CALCULATION =====
    const vuln_contribution = $HRP_Vuln_Weight * s_vuln;
    const supply_contribution = $HRP_Supply_Weight * s_supply;
    const topo_contribution = $HRP_Topology_Weight * s_topo;
    const aging_contribution = $HRP_Aging_Weight * s_aging;
    
    const overall_score = vuln_contribution + supply_contribution + topo_contribution + aging_contribution;
    const hrp_score = Math.min(Math.round(overall_score), 100);

    debugOutput.final_calculation = {
        vuln_contribution: vuln_contribution,
        supply_contribution: supply_contribution,
        topo_contribution: topo_contribution,
        aging_contribution: aging_contribution,
        overall_score: overall_score,
        hrp_score_capped: hrp_score,
        formula: `(${$HRP_Vuln_Weight} × ${s_vuln.toFixed(2)}) + (${$HRP_Supply_Weight} × ${s_supply.toFixed(2)}) + (${$HRP_Topology_Weight} × ${s_topo.toFixed(2)}) + (${$HRP_Aging_Weight} × ${s_aging.toFixed(2)})`
    };

    debugOutput.contribution_ratios = {
        vulnerability_percentage: overall_score > 0 ? parseFloat(((vuln_contribution / overall_score) * 100).toFixed(1)) : 0,
        supply_chain_percentage: overall_score > 0 ? parseFloat(((supply_contribution / overall_score) * 100).toFixed(1)) : 0,
        topology_percentage: overall_score > 0 ? parseFloat(((topo_contribution / overall_score) * 100).toFixed(1)) : 0,
        aging_percentage: overall_score > 0 ? parseFloat(((aging_contribution / overall_score) * 100).toFixed(1)) : 0
    };

    // ===== ISSUES DETECTION =====
    debugOutput.detected_issues = [];
    
    if (totalLib === 0) {
        debugOutput.detected_issues.push({
            component: "Supply Chain",
            issue: "No libraries found in query results",
            suggestion: "Check that process groups have software components detected. Library query may be returning empty results."
        });
    } else if (vulnLib === 0) {
        debugOutput.detected_issues.push({
            component: "Supply Chain",
            issue: "No vulnerable libraries detected",
            suggestion: "All libraries are clean (no vulnerabilities), resulting in 0% supply chain risk."
        });
    }

    if (data.total_related_entities === 0 || data.total_related_entities === null) {
        debugOutput.detected_issues.push({
            component: "Topology",
            issue: "No related entities found",
            suggestion: "Vulnerability events may not have related_entities data populated. Check vulnerability event schema."
        });
    }

    if (raw_aging_score === 0) {
        debugOutput.detected_issues.push({
            component: "Aging",
            issue: "Aging score is 0",
            suggestion: "Check if vulnerability.parent.first_seen is populated. Age calculation may be failing."
        });
    }

    debugOutput.recommendations = [
        "Review the 'detected_issues' array for specific problems",
        "Check 'raw_query_results' to see what data is being returned",
        "Verify that dashboard variables are set correctly (see 'input_variables')",
        "If supply chain is 0%, verify that library query is returning data",
        "If topology is 0%, check that vulnerability events have related_entities populated",
        "Compare raw scores (s_vuln, s_supply, s_topo, s_aging) to expected ranges (0-100)"
    ];

    return [debugOutput];
}
