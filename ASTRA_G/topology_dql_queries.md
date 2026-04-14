# Topology Risk Calculation with DQL Queries

This document explains how to calculate HRP v2.0 Topology Risk using Dynatrace Query Language (DQL) for a specific Process Group.

**Target Process Group**: `PROCESS_GROUP-EFBDE5651A9A5A36`

---

## ⚠️ DQL Limitations for Graph Traversal

**Important**: DQL does **NOT** support:
- ❌ Recursive queries or CTEs
- ❌ Multi-hop graph traversal (BFS/DFS)
- ❌ Direct relationship chaining beyond 1 level

**What IS possible**:
- ✅ Query vulnerabilities for affected entities (blast radius)
- ✅ Fetch direct relationships (1-hop only)
- ✅ Identify entity types for critical path analysis
- ✅ Use multiple queries to build a 3-hop graph manually

---

## Query 1: Blast Radius - Count Affected Entities

This query finds all vulnerabilities affecting our target Process Group and counts unique affected entities.

```dql
// Blast Radius: Count all entities affected by vulnerabilities in this PG
fetch dt.security.vulnerability
| filter affected.entity == "PROCESS_GROUP-EFBDE5651A9A5A36"
| fields 
    vulnerability_id = vulnerability.id,
    affected_entity = affected.entity,
    entity_name = affected.entity.name,
    entity_type = affected.entity.type,
    vulnerability_display_id = vulnerability.display.id,
    vulnerability_title = vulnerability.title,
    risk_score = vulnerability.davis_assessment.score
| summarize 
    total_vulnerabilities = count(),
    unique_affected_entities = countDistinct(affected_entity),
    entity_types = collectDistinct(entity_type)
| fields 
    unique_affected_entities,
    total_vulnerabilities,
    entity_types,
    blast_score = 100 * (1 - exp(-0.05 * unique_affected_entities))
```

**Output Example**:
```
unique_affected_entities: 5
total_vulnerabilities: 12
entity_types: ["PROCESS_GROUP_INSTANCE", "HOST", "SERVICE"]
blast_score: 22.12
```

---

## Query 2: Direct Relationships (1-Hop Connectivity)

This query fetches entities that are **directly connected** to our Process Group (1 hop only).

```dql
// Get direct relationships for the Process Group
fetch dt.entity.process_group
| filter id == "PROCESS_GROUP-EFBDE5651A9A5A36"
| fields
    pg_id = id,
    pg_name = entity.name,
    // Calls relationships
    calls_services = toString(calls),
    // Runs on relationships
    runs_on_hosts = toString(runs_on),
    // Is instance of
    is_instance_of = toString(is_instance_of),
    // Process group instances
    pg_instances = toString(has_instance)
```

**Alternative - Query Services Called by PG**:
```dql
// Find all services called by this Process Group
fetch dt.entity.service
| filter called_by == "PROCESS_GROUP-EFBDE5651A9A5A36"
| fields
    service_id = id,
    service_name = entity.name,
    service_type = entity.type
| summarize
    direct_services_count = count(),
    service_ids = collectArray(service_id)
```

---

## Query 3: 2-Hop Relationships (Manual Chain)

To get 2-hop relationships, you need to run a second query using results from Query 2.

**Step 1**: Get direct services (from Query 2 results)

**Step 2**: Query what those services call:
```dql
// Replace with actual service IDs from previous query
fetch dt.entity.service
| filter id in [
    "SERVICE-1234567890ABCDEF",  // Replace with real IDs
    "SERVICE-FEDCBA0987654321"
]
| fields
    service_id = id,
    service_name = entity.name,
    // What these services call
    calls_databases = toString(calls[entity.type == "DATABASE"]),
    calls_other_services = toString(calls[entity.type == "SERVICE"]),
    runs_on_hosts = toString(runs_on)
```

---

## Query 4: 3-Hop Relationships (Third Query)

Repeat the process for a third hop using results from the 2-hop query.

```dql
// Query entities discovered at 2-hop level
fetch dt.entity.database
| filter id in [
    "DATABASE-ABC123",  // Replace with IDs from 2-hop query
    "DATABASE-XYZ789"
]
| fields
    db_id = id,
    db_name = entity.name,
    runs_on_hosts = toString(runs_on)
```

---

## Query 5: Critical Path Analysis

Identify if vulnerable entities are "critical" types (databases, services, K8s).

```dql
// Critical Path: Check entity types of vulnerable entities
fetch dt.security.vulnerability
| filter affected.entity == "PROCESS_GROUP-EFBDE5651A9A5A36"
| fields
    affected_entity = affected.entity,
    entity_type = affected.entity.type,
    entity_name = affected.entity.name,
    is_critical = if(
        entity_type == "SERVICE" or
        entity_type == "DATABASE" or
        entity_type == "KUBERNETES_CLUSTER" or
        entity_type == "APPLICATION",
        true,
        false
    )
| summarize
    total_entities = countDistinct(affected_entity),
    critical_entities = countDistinct(affected_entity, if(is_critical)),
    critical_percentage = (countDistinct(affected_entity, if(is_critical)) * 100.0) / countDistinct(affected_entity)
| fields
    total_entities,
    critical_entities,
    critical_percentage,
    critical_path_score = critical_percentage
```

---

## Query 6: Combined Calculation (Single Process Group)

This query combines blast radius and critical path in one query:

```dql
// Combined: Blast Radius + Critical Path for specific Process Group
fetch dt.security.vulnerability
| filter affected.entity == "PROCESS_GROUP-EFBDE5651A9A5A36"
| fields
    affected_entity = affected.entity,
    entity_type = affected.entity.type,
    vulnerability_id = vulnerability.id
| summarize
    // Blast radius metrics
    total_vulnerabilities = countDistinct(vulnerability_id),
    unique_entities = countDistinct(affected_entity),
    
    // Critical path metrics
    critical_entities = countDistinct(affected_entity, 
        if(entity_type == "SERVICE" or 
           entity_type == "DATABASE" or 
           entity_type == "KUBERNETES_CLUSTER" or 
           entity_type == "APPLICATION")
    )
| fields
    unique_entities,
    total_vulnerabilities,
    critical_entities,
    
    // Component scores
    blast_score = 100 * (1 - exp(-0.05 * unique_entities)),
    critical_path_score = if(unique_entities > 0, 
        (critical_entities * 100.0) / unique_entities, 
        0
    )
| fields
    // Final topology score (without connectivity - we can't get that in DQL)
    // Using simplified formula: 70% blast + 30% critical (no connectivity component)
    topology_score_simplified = (0.70 * blast_score) + (0.30 * critical_path_score),
    blast_score,
    critical_path_score,
    unique_entities,
    critical_entities,
    total_vulnerabilities
```

---

## 🔴 The Connectivity Problem

**Why we can't calculate connectivity in DQL**:

DQL does not support:
1. **Recursive queries**: Can't follow relationships to depth N
2. **Graph algorithms**: No BFS/DFS functions
3. **Variable-depth JOINs**: Can't dynamically expand relationships

**Workaround Options**:

### Option A: Multi-Query Approach (JavaScript/Python)
```javascript
// Run 3 queries sequentially, building the graph
const hop1Entities = await queryExecutionClient.queryExecute({
    body: { query: getDirectRelationshipsQuery(targetPG) }
});

const hop2Entities = await queryExecutionClient.queryExecute({
    body: { query: getDirectRelationshipsQuery(hop1Entities) }
});

const hop3Entities = await queryExecutionClient.queryExecute({
    body: { query: getDirectRelationshipsQuery(hop2Entities) }
});

// Calculate transitive count
const transitiveCount = (hop1 + hop2 + hop3).size - initialAffectedCount;
```

### Option B: Pre-calculate in Backend
Run the full topology calculation in your Python script (astra_report.py) and store results in a custom metric or event:

```dql
// Query pre-calculated topology scores
fetch events
| filter event.type == "CUSTOM_INFO"
| filter event.name == "hrp_topology_score"
| filter dt.entity.process_group == "PROCESS_GROUP-EFBDE5651A9A5A36"
| fields
    timestamp,
    topology_score = toDouble(event.topology_score),
    blast_score = toDouble(event.blast_score),
    connectivity_score = toDouble(event.connectivity_score),
    critical_path_score = toDouble(event.critical_path_score)
| sort timestamp desc
| limit 1
```

### Option C: Use Smartscape API Instead
For full connectivity analysis, use the **Dynatrace Smartscape API** to fetch the entity graph, then calculate in JavaScript:

```javascript
// Use Dynatrace API, not DQL
const response = await fetch(
    `${DT_URL}/api/v2/entities/${entityId}?fields=+fromRelationships,+toRelationships`,
    { headers: { 'Authorization': `Api-Token ${DT_TOKEN}` } }
);
```

---

## Complete Example: DQL-Based Simplified Topology Score

This query calculates a **simplified topology score** using only what's available in DQL:

```dql
// Full Topology Score Calculation (Simplified - No Connectivity)
// For Process Group: PROCESS_GROUP-EFBDE5651A9A5A36

fetch dt.security.vulnerability, from: now()-30d
| filter affected.entity starts "PROCESS_GROUP-EFBDE5651A9A5A36"
| expand affected.entities
| fields
    vulnerability_id = vulnerability.id,
    affected_entity = array.affected.entity,
    entity_type = array.affected.entity.type,
    risk_score = vulnerability.davis_assessment.score,
    exposure = vulnerability.davis_assessment.exposure,
    vulnerable_component = affected.vulnerable.component.name
| summarize {
    // Count metrics
    total_vulnerabilities = countDistinct(vulnerability_id),
    unique_entities = countDistinct(affected_entity),
    
    // Critical entity metrics
    critical_entities = countDistinct(affected_entity, 
        if(
            entity_type in ["SERVICE", "DATABASE", "KUBERNETES_CLUSTER", "APPLICATION"]
        )
    ),
    
    // Average risk
    avg_risk = avg(risk_score)
}, by: {}
| fieldsAdd
    // === Component 1: Blast Radius ===
    blast_score = 100 * (1 - exp(-0.05 * unique_entities)),
    
    // === Component 3: Critical Path ===
    critical_path_score = if(
        unique_entities > 0,
        (critical_entities * 100.0) / unique_entities,
        0
    )
| fieldsAdd
    // === Final Topology Score (Simplified) ===
    // Note: Missing connectivity component (can't calculate in DQL)
    // Using 70/30 split instead of 40/35/25
    topology_score = (0.70 * blast_score) + (0.30 * critical_path_score)
| fields
    // Output
    topology_score,
    blast_score,
    critical_path_score,
    connectivity_score = 0.0,  // Not available in DQL
    unique_entities,
    critical_entities,
    total_vulnerabilities,
    avg_risk,
    
    // Metadata
    note = "Connectivity score unavailable - requires multi-hop graph traversal not supported in DQL"
```

---

## Summary

| Component | DQL Support | Method |
|-----------|-------------|--------|
| **Blast Radius** | ✅ Full | Count unique affected entities |
| **Connectivity (1-hop)** | ✅ Partial | Query direct relationships |
| **Connectivity (3-hop)** | ❌ No | Requires 3 separate queries + JavaScript |
| **Critical Path** | ✅ Full | Check entity types |
| **Overall Score** | ⚠️ Simplified | Missing connectivity component |

**Recommendation**: 
- Use DQL for **blast radius** and **critical path** 
- Calculate **connectivity** in JavaScript/Python using multiple DQL queries or Smartscape API
- For dashboards, pre-calculate full scores in backend and query results via DQL
