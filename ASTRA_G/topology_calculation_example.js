/**
 * HRP v2.0 Topology Risk Calculation - NodeJS Implementation
 * 
 * This matches the exact Python logic from astra_report.py
 * Calculates topology risk with blast radius, connectivity depth, and critical path analysis
 */

/**
 * Calculate transitive risk using BFS to find all entities connected to vulnerable ones.
 * 
 * @param {Set<string>} vulnerableEntities - Set of entity IDs with vulnerabilities
 * @param {Object} entityGraph - Dictionary mapping entity_id -> [connected_entity_ids]
 * @param {number} maxDepth - Maximum hops to traverse (default 3)
 * @returns {Set<string>} Set of all entities within maxDepth hops of vulnerable entities
 */
function calculateTransitiveRisk(vulnerableEntities, entityGraph, maxDepth = 3) {
    const visited = new Set();
    const queue = [];
    
    // Initialize queue with vulnerable entities at depth 0
    for (const entity of vulnerableEntities) {
        queue.push({ entityId: entity, depth: 0 });
    }
    
    while (queue.length > 0) {
        const { entityId, depth } = queue.shift(); // Dequeue
        
        // Skip if already visited or exceeded max depth
        if (visited.has(entityId) || depth > maxDepth) {
            continue;
        }
        
        visited.add(entityId);
        
        // Add connected entities to queue
        if (entityGraph[entityId]) {
            for (const connectedId of entityGraph[entityId]) {
                if (!visited.has(connectedId)) {
                    queue.push({ entityId: connectedId, depth: depth + 1 });
                }
            }
        }
    }
    
    return visited;
}

/**
 * Calculate topology risk with exponential and power-law functions (0-100 scale).
 * 
 * Includes:
 * - Blast radius (affected entities count)
 * - Connectivity depth (service dependency chains)
 * - Critical path analysis (databases, services, K8s)
 * 
 * @param {Array} vulnerabilities - Array of vulnerability objects
 * @param {Object} data - Dynatrace data (process_groups, hosts, etc.)
 * @param {Object} config - Configuration object
 * @returns {number} Topology score (0-100)
 */
function calculateHRPv2Topology(vulnerabilities, data, config) {
    // Get config parameters
    const blastDecay = config.blast_radius_decay || 0.05;
    const enableConnectivity = config.enable_connectivity_analysis !== false; // Default true
    
    // Track affected entities and relationships
    const affectedEntities = new Set();
    const entityRelationships = {}; // Graph: entity_id -> [connected_entity_ids]
    const vulnerableEntityTypes = {}; // entity_id -> type (HOST, PROCESS, etc.)
    
    // === Step 1: Extract affected entities from vulnerabilities ===
    for (const vuln of vulnerabilities) {
        const remediationItems = vuln.remediationItems || [];
        for (const item of remediationItems) {
            const entityId = item.id;
            const entityType = item.type || 'UNKNOWN';
            if (entityId) {
                affectedEntities.add(entityId);
                vulnerableEntityTypes[entityId] = entityType;
            }
        }
    }
    
    // === Step 2: Build connectivity graph from Dynatrace relationships ===
    if (enableConnectivity) {
        // Process group relationships
        const processGroups = data.process_groups || [];
        for (const pg of processGroups) {
            const pgId = pg.entityId;
            if (pgId) {
                entityRelationships[pgId] = [];
                
                // Parent relationships (isInstanceOf)
                if (pg.fromRelationships?.isInstanceOf) {
                    for (const parent of pg.fromRelationships.isInstanceOf) {
                        if (parent.id) {
                            entityRelationships[pgId].push(parent.id);
                        }
                    }
                }
                
                // Service calls (toRelationships)
                if (pg.toRelationships) {
                    const relationshipTypes = ['calls', 'runsOn', 'isProcessOf'];
                    for (const relType of relationshipTypes) {
                        if (pg.toRelationships[relType]) {
                            for (const target of pg.toRelationships[relType]) {
                                if (target.id) {
                                    entityRelationships[pgId].push(target.id);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // Host relationships
        const hosts = data.hosts || [];
        for (const host of hosts) {
            const hostId = host.entityId;
            if (hostId) {
                entityRelationships[hostId] = [];
                
                // Process relationships (isProcessOf)
                if (host.toRelationships?.isProcessOf) {
                    for (const process of host.toRelationships.isProcessOf) {
                        if (process.id) {
                            entityRelationships[hostId].push(process.id);
                        }
                    }
                }
            }
        }
    }
    
    // === Component 1: Blast Radius (entity count) ===
    const entityCount = affectedEntities.size;
    const blastScore = 100 * (1 - Math.exp(-blastDecay * entityCount));
    
    console.log(`\n=== Blast Radius ===`);
    console.log(`Affected entities: ${entityCount}`);
    console.log(`Formula: 100 * (1 - e^(-${blastDecay} * ${entityCount}))`);
    console.log(`Blast Score: ${blastScore.toFixed(2)}`);
    
    // === Component 2: Connectivity Depth (transitive risk) ===
    let connectivityScore = 0;
    if (enableConnectivity && Object.keys(entityRelationships).length > 0) {
        // Calculate transitive risk using BFS from vulnerable entities
        const connectedEntities = calculateTransitiveRisk(
            affectedEntities,
            entityRelationships,
            3 // max_depth
        );
        
        // Score based on how many additional entities are at risk
        const transitiveCount = connectedEntities.size - affectedEntities.size;
        
        console.log(`\n=== Connectivity Depth ===`);
        console.log(`Total connected entities (within 3 hops): ${connectedEntities.size}`);
        console.log(`Transitive entities (not directly affected): ${transitiveCount}`);
        
        if (transitiveCount > 0) {
            // Power-law: lots of connections = exponentially worse
            connectivityScore = Math.min(100, 100 * Math.pow(transitiveCount / 50, 0.6));
            console.log(`Formula: min(100, 100 * (${transitiveCount}/50)^0.6)`);
            console.log(`Connectivity Score: ${connectivityScore.toFixed(2)}`);
        } else {
            console.log(`No transitive entities found`);
            console.log(`Connectivity Score: 0.00`);
        }
    }
    
    // === Component 3: Critical Path Analysis (database/network exposure) ===
    let criticalPathScore = 0;
    if (enableConnectivity) {
        // Check if vulnerable entities are "critical" types
        const criticalTypes = ['DATABASE_CONNECTION_FAILURE', 'SERVICE', 'APPLICATION', 'KUBERNETES_CLUSTER'];
        let criticalCount = 0;
        
        for (const [entityId, entityType] of Object.entries(vulnerableEntityTypes)) {
            if (criticalTypes.some(crit => entityType.includes(crit))) {
                criticalCount++;
            }
        }
        
        console.log(`\n=== Critical Path Analysis ===`);
        console.log(`Critical entities: ${criticalCount}/${affectedEntities.size}`);
        
        if (criticalCount > 0) {
            criticalPathScore = Math.min(100, (criticalCount / affectedEntities.size) * 100);
            console.log(`Formula: min(100, (${criticalCount}/${affectedEntities.size}) * 100)`);
            console.log(`Critical Path Score: ${criticalPathScore.toFixed(2)}`);
        } else {
            console.log(`No critical entities found`);
            console.log(`Critical Path Score: 0.00`);
        }
    }
    
    // === Weighted Topology Score ===
    let topologyScore;
    if (enableConnectivity) {
        // With connectivity: 40% blast + 35% connectivity + 25% critical
        topologyScore = (0.40 * blastScore + 
                        0.35 * connectivityScore +
                        0.25 * criticalPathScore);
        
        console.log(`\n=== Final Topology Score ===`);
        console.log(`Formula: (0.40 × ${blastScore.toFixed(2)}) + (0.35 × ${connectivityScore.toFixed(2)}) + (0.25 × ${criticalPathScore.toFixed(2)})`);
        console.log(`       = ${(0.40 * blastScore).toFixed(2)} + ${(0.35 * connectivityScore).toFixed(2)} + ${(0.25 * criticalPathScore).toFixed(2)}`);
    } else {
        // Without connectivity: 100% blast radius only
        topologyScore = blastScore;
        
        console.log(`\n=== Final Topology Score ===`);
        console.log(`Formula: Blast Score only (connectivity disabled)`);
    }
    
    topologyScore = Math.min(topologyScore, 100);
    console.log(`Topology Score: ${topologyScore.toFixed(2)} / 100`);
    
    return topologyScore;
}

// ============================================================================
// EXAMPLE USAGE
// ============================================================================

// Example vulnerabilities data
const exampleVulnerabilities = [
    {
        remediationItems: [
            { id: 'PROCESS_GROUP-1234', type: 'PROCESS_GROUP_INSTANCE' },
            { id: 'PROCESS_GROUP-5678', type: 'PROCESS_GROUP_INSTANCE' },
            { id: 'HOST-ABCD', type: 'HOST' }
        ]
    },
    {
        remediationItems: [
            { id: 'PROCESS_GROUP-9999', type: 'PROCESS_GROUP_INSTANCE' },
            { id: 'SERVICE-DB01', type: 'SERVICE' },
            { id: 'HOST-EFGH', type: 'HOST' }
        ]
    }
];

// Example Dynatrace topology data
const exampleData = {
    process_groups: [
        {
            entityId: 'PROCESS_GROUP-1234',
            fromRelationships: {
                isInstanceOf: [{ id: 'PROCESS_GROUP_INSTANCE-1' }]
            },
            toRelationships: {
                calls: [
                    { id: 'SERVICE-API01' },
                    { id: 'SERVICE-DB01' }
                ],
                runsOn: [{ id: 'HOST-ABCD' }]
            }
        },
        {
            entityId: 'PROCESS_GROUP-5678',
            toRelationships: {
                calls: [{ id: 'SERVICE-API01' }]
            }
        },
        {
            entityId: 'PROCESS_GROUP-9999',
            toRelationships: {
                calls: [{ id: 'SERVICE-CACHE01' }]
            }
        }
    ],
    hosts: [
        {
            entityId: 'HOST-ABCD',
            toRelationships: {
                isProcessOf: [
                    { id: 'PROCESS_GROUP-1234' },
                    { id: 'PROCESS_GROUP-5678' }
                ]
            }
        },
        {
            entityId: 'HOST-EFGH',
            toRelationships: {
                isProcessOf: [{ id: 'PROCESS_GROUP-9999' }]
            }
        }
    ]
};

// Configuration
const config = {
    blast_radius_decay: 0.05,
    enable_connectivity_analysis: true
};

// Run the calculation
console.log('╔═══════════════════════════════════════════════════════════╗');
console.log('║  HRP v2.0 Topology Risk Calculation - NodeJS Example     ║');
console.log('╚═══════════════════════════════════════════════════════════╝');

const topologyScore = calculateHRPv2Topology(
    exampleVulnerabilities,
    exampleData,
    config
);

console.log('\n╔═══════════════════════════════════════════════════════════╗');
console.log(`║  FINAL RESULT: ${topologyScore.toFixed(2)} / 100${' '.repeat(35 - topologyScore.toFixed(2).length)}║`);
console.log('╚═══════════════════════════════════════════════════════════╝');

// Export for use in other modules
module.exports = {
    calculateHRPv2Topology,
    calculateTransitiveRisk
};
