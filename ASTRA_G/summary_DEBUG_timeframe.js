import { queryExecutionClient } from '@dynatrace-sdk/client-query';

/**
 * DEBUG Tile for Timeframe Issues
 * Tests timeframe queries vs no-timeframe queries to diagnose data loss
 */

async function fetchWithTimeframe(tagfilter, tagkey, tagvalue, pgi_name, timeframe_from, timeframe_to) {
  console.log("=== TIMEFRAME DEBUG ===");
  console.log("Raw timeframe_from:", timeframe_from);
  console.log("Raw timeframe_to:", timeframe_to);
  console.log("Type of timeframe_from:", typeof timeframe_from);
  console.log("Type of timeframe_to:", typeof timeframe_to);
  
  const fromMs = new Date(timeframe_from).getTime();
  const toMs = new Date(timeframe_to).getTime();
  
  console.log("Converted fromMs:", fromMs);
  console.log("Converted toMs:", toMs);
  console.log("Is fromMs valid?", !isNaN(fromMs));
  console.log("Is toMs valid?", !isNaN(toMs));
  
  const fromDate = new Date(fromMs);
  const toDate = new Date(toMs);
  console.log("From Date:", fromDate.toISOString());
  console.log("To Date:", toDate.toISOString());
  console.log("Time range (hours):", (toMs - fromMs) / (1000 * 60 * 60));

  const query = String.raw`fetch events, from: ${fromMs}, to: ${toMs}
| filter event.kind=="SECURITY_EVENT"
| filter event.category=="VULNERABILITY_MANAGEMENT"
| filter event.provider=="Dynatrace"
| filter event.type=="VULNERABILITY_STATE_REPORT_EVENT"
| filter event.level=="ENTITY"
| filter vulnerability.resolution.status == "OPEN" and vulnerability.mute.status == "NOT_MUTED"
| dedup vulnerability.id, affected_entity.id
| expand pid=affected_entity.affected_processes.ids
| lookup [
  fetch dt.entity.process_group_instance
  | fieldsAdd tags, alias:pgi.tags
  | fields process_id=id, pgi.tags, process_name=entity.name
  | filter matchesPhrase(process_name, "${pgi_name}") OR ("${pgi_name}"== "ALL")
  ], sourceField: pid, lookupField:process_id, fields:{process_id,process_name, pgi.tags}
| filter ("${tagfilter}" == "ON" AND in(concat("${tagkey}", ":", "${tagvalue}"), pgi.tags)) OR ("${tagfilter}" == "OFF" AND isNotNull(vulnerability.id))
| dedup vulnerability.id, pid
| summarize count()`;

  console.log("\n=== QUERY WITH TIMEFRAME ===");
  console.log(query);
  
  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000 }
  });
  
  return response.result.records ?? [];
}

async function fetchWithoutTimeframe(tagfilter, tagkey, tagvalue, pgi_name) {
  const query = String.raw`fetch events
| filter event.kind=="SECURITY_EVENT"
| filter event.category=="VULNERABILITY_MANAGEMENT"
| filter event.provider=="Dynatrace"
| filter event.type=="VULNERABILITY_STATE_REPORT_EVENT"
| filter event.level=="ENTITY"
| filter vulnerability.resolution.status == "OPEN" and vulnerability.mute.status == "NOT_MUTED"
| dedup vulnerability.id, affected_entity.id
| expand pid=affected_entity.affected_processes.ids
| lookup [
  fetch dt.entity.process_group_instance
  | fieldsAdd tags, alias:pgi.tags
  | fields process_id=id, pgi.tags, process_name=entity.name
  | filter matchesPhrase(process_name, "${pgi_name}") OR ("${pgi_name}"== "ALL")
  ], sourceField: pid, lookupField:process_id, fields:{process_id,process_name, pgi.tags}
| filter ("${tagfilter}" == "ON" AND in(concat("${tagkey}", ":", "${tagvalue}"), pgi.tags)) OR ("${tagfilter}" == "OFF" AND isNotNull(vulnerability.id))
| dedup vulnerability.id, pid
| summarize count()`;

  console.log("\n=== QUERY WITHOUT TIMEFRAME ===");
  console.log(query);
  
  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000 }
  });
  
  return response.result.records ?? [];
}

async function testEventTimestamps(timeframe_from, timeframe_to) {
  const fromMs = new Date(timeframe_from).getTime();
  const toMs = new Date(timeframe_to).getTime();
  
  const query = String.raw`fetch events, from: ${fromMs}, to: ${toMs}
| filter event.kind=="SECURITY_EVENT"
| filter event.category=="VULNERABILITY_MANAGEMENT"
| filter event.provider=="Dynatrace"
| filter event.type=="VULNERABILITY_STATE_REPORT_EVENT"
| fields timestamp, event.id, vulnerability.id, vulnerability.title
| sort timestamp desc
| limit 10`;

  console.log("\n=== SAMPLE EVENTS IN TIMEFRAME ===");
  
  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000 }
  });
  
  const events = response.result.records ?? [];
  console.log(`Found ${events.length} sample events in timeframe`);
  
  events.forEach((event, i) => {
    const eventDate = new Date(Number(event.timestamp));
    console.log(`${i+1}. Event timestamp: ${eventDate.toISOString()} | Vuln: ${event['vulnerability.id']}`);
  });
  
  return events;
}

async function testAllEventTimestamps() {
  const query = String.raw`fetch events
| filter event.kind=="SECURITY_EVENT"
| filter event.category=="VULNERABILITY_MANAGEMENT"
| filter event.provider=="Dynatrace"
| filter event.type=="VULNERABILITY_STATE_REPORT_EVENT"
| fields timestamp, event.id, vulnerability.id
| sort timestamp desc
| limit 10`;

  console.log("\n=== SAMPLE EVENTS (NO TIMEFRAME) ===");
  
  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000 }
  });
  
  const events = response.result.records ?? [];
  console.log(`Found ${events.length} sample events (all time)`);
  
  events.forEach((event, i) => {
    const ts = event.timestamp;
    try {
      const eventDate = new Date(Number(ts));
      if (isNaN(eventDate.getTime())) {
        console.log(`${i+1}. Event timestamp: INVALID (${ts}) | Vuln: ${event['vulnerability.id']}`);
      } else {
        console.log(`${i+1}. Event timestamp: ${eventDate.toISOString()} | Vuln: ${event['vulnerability.id']}`);
      }
    } catch (e) {
      console.log(`${i+1}. Event timestamp: ERROR (${ts}) | Vuln: ${event['vulnerability.id']}`);
    }
  });
  
  return events;
}

async function testVulnFirstSeen(timeframe_from, timeframe_to) {
  const fromMs = new Date(timeframe_from).getTime();
  const toMs = new Date(timeframe_to).getTime();
  
  const query = String.raw`fetch events
| filter event.kind=="SECURITY_EVENT"
| filter event.category=="VULNERABILITY_MANAGEMENT"
| filter event.provider=="Dynatrace"
| filter event.type=="VULNERABILITY_STATE_REPORT_EVENT"
| filter vulnerability.resolution.status == "OPEN"
| fields timestamp, vulnerability.parent.first_seen, vulnerability.id, vulnerability.title
| fieldsAdd first_seen_ms = vulnerability.parent.first_seen
| fieldsAdd in_timeframe = (first_seen_ms >= ${fromMs} and first_seen_ms <= ${toMs})
| summarize 
    total = count(),
    in_timeframe_count = countIf(in_timeframe),
    before_timeframe = countIf(first_seen_ms < ${fromMs}),
    after_timeframe = countIf(first_seen_ms > ${toMs})`;

  console.log("\n=== VULNERABILITY FIRST_SEEN ANALYSIS ===");
  
  const response = await queryExecutionClient.queryExecute({ 
    body: { query, requestTimeoutMilliseconds: 60000 }
  });
  
  const result = response.result.records[0] ?? {};
  console.log(`Total vulnerabilities: ${result.total || 0}`);
  console.log(`First seen IN timeframe: ${result.in_timeframe_count || 0}`);
  console.log(`First seen BEFORE timeframe: ${result.before_timeframe || 0}`);
  console.log(`First seen AFTER timeframe: ${result.after_timeframe || 0}`);
  
  return result;
}

export default async function () {
    console.log("========================================");
    console.log("TIMEFRAME DEBUG DIAGNOSTICS");
    console.log("========================================");
    
    // Test 1: Check timeframe values
    console.log("\n### TEST 1: Dashboard Timeframe Variables ###");
    console.log("$dt_timeframe_from:", $dt_timeframe_from);
    console.log("$dt_timeframe_to:", $dt_timeframe_to);
    
    // Test 2: Fetch with timeframe
    console.log("\n### TEST 2: Query WITH Timeframe ###");
    const withTimeframe = await fetchWithTimeframe($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains, $dt_timeframe_from, $dt_timeframe_to);
    const countWith = withTimeframe[0] ? Number(withTimeframe[0]['count()']) : 0;
    console.log("Result with timeframe:", countWith, "vulnerabilities");
    
    // Test 3: Fetch without timeframe
    console.log("\n### TEST 3: Query WITHOUT Timeframe ###");
    const withoutTimeframe = await fetchWithoutTimeframe($Tag_Filter, $Tag_Key, $Tag_Value, $process_name_contains);
    const countWithout = withoutTimeframe[0] ? Number(withoutTimeframe[0]['count()']) : 0;
    console.log("Result without timeframe:", countWithout, "vulnerabilities");
    
    // Test 4: Sample events in timeframe
    console.log("\n### TEST 4: Sample Events in Selected Timeframe ###");
    await testEventTimestamps($dt_timeframe_from, $dt_timeframe_to);
    
    // Test 5: Sample events all time
    console.log("\n### TEST 5: Sample Events (All Time) ###");
    await testAllEventTimestamps();
    
    // Test 6: Vulnerability first_seen analysis
    console.log("\n### TEST 6: Vulnerability Discovery Time Analysis ###");
    const firstSeenAnalysis = await testVulnFirstSeen($dt_timeframe_from, $dt_timeframe_to);
    
    // Test 7: Compare
    console.log("\n### TEST 7: Comparison ###");
    const diff = countWithout - countWith;
    const pct = countWithout > 0 ? ((diff / countWithout) * 100).toFixed(1) : 0;
    console.log(`Data loss: ${diff} vulnerabilities (${pct}%)`);
    
    const firstSeenInWindow = firstSeenAnalysis.in_timeframe_count || 0;
    const firstSeenBefore = firstSeenAnalysis.before_timeframe || 0;
    
    console.log(`\nVulnerabilities discovered:`);
    console.log(`  - BEFORE timeframe: ${firstSeenBefore}`);
    console.log(`  - IN timeframe: ${firstSeenInWindow}`);
    console.log(`  - AFTER timeframe: ${firstSeenAnalysis.after_timeframe || 0}`);
    
    if (diff > 0) {
        console.log("\n⚠️ ROOT CAUSE IDENTIFIED!");
        console.log("=========================");
        console.log("Vulnerability State Reports are CURRENT STATE snapshots, not time-series events.");
        console.log(`${firstSeenBefore} vulnerabilities were discovered BEFORE your timeframe.`);
        console.log("Using 'fetch events, from:X, to:Y' filters by EVENT INGESTION time, not vulnerability discovery.");
        console.log("\n💡 SOLUTION:");
        console.log("1. Remove timeframe from 'fetch events' queries");
        console.log("2. Use vulnerability.parent.first_seen for historical analysis");
        console.log("3. Keep queries showing CURRENT state (all open vulnerabilities)");
    } else {
        console.log("\n✅ No data loss detected - timeframe working correctly");
    }
    
    console.log("\n========================================");
    console.log("END DIAGNOSTICS");
    console.log("========================================");

    // Return markdown summary
    return `
# 🔍 Timeframe Debug Report

## Dashboard Timeframe
- **From:** ${$dt_timeframe_from}
- **To:** ${$dt_timeframe_to}
- **Range:** ${((new Date($dt_timeframe_to).getTime() - new Date($dt_timeframe_from).getTime()) / (1000 * 60 * 60)).toFixed(1)} hours

## Results

| Query Type | Count | Status |
|-----------|-------|--------|
| **WITH Timeframe** | ${countWith} | ${countWith > 0 ? '✅' : '❌'} |
| **WITHOUT Timeframe** | ${countWithout} | ${countWithout > 0 ? '✅' : '❌'} |

## Data Loss Analysis

${diff > 0 ? `
### ⚠️ **ISSUE DETECTED**

- **Missing:** ${diff} vulnerabilities (${pct}%)
- **Cause:** Timeframe filter is removing data

### Possible Solutions:

1. **Check Event Timestamps**: Vulnerability events may use a different timestamp field
2. **Widen Timeframe**: Current window might be too narrow
3. **Use Event Creation Time**: Events might be indexed by creation, not discovery time
4. **Remove Timeframe from Vulnerability Queries**: Security events are snapshots, not time-series

### Recommendation:
For vulnerability management dashboards, consider using **current state queries** without timeframe filters, as vulnerabilities represent the CURRENT security posture, not historical events.

The timeframe should apply to:
- ✅ Attack/exploitation events
- ✅ Security incidents
- ❌ Vulnerability state (always show current)
` : `
### ✅ **NO ISSUES**

Timeframe filtering is working correctly. Data is consistent between queries.
`}

---

**Check console logs for detailed diagnostics**
`;
}
