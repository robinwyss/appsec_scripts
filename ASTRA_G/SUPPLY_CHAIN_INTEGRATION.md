# Supply Chain Component Integration - HRPv2 Dashboard

## Overview
This document explains how the Supply Chain component is calculated in the HRPv2 Dashboard and why it uses a hybrid approach.

## The Challenge
The ideal supply chain calculation requires:
1. Fetching all software components for filtered process group instances
2. Deduplicating packages by name and version
3. Matching with vulnerability data to identify vulnerable packages
4. Calculating the ratio: `vulnerable_packages / total_packages`

However, this creates a technical challenge:
- **Main HRP Query** starts with `fetch security.events` (vulnerability data)
- **Supply Chain Query** starts with `fetch dt.entity.process_group_instance` (software component data)

## Solution: Hybrid Approach

### 1. Main HRP Score Query (hrp_overall_score)
**Purpose:** Fast, real-time overall risk score  
**Starting Point:** `fetch security.events`  
**Supply Chain Calculation:**
```dql
fieldsAdd supply_score=100 * sqrt(unique_packages / toDouble($Expected_Total_Packages))
```
- Uses `unique_packages` (count of vulnerable packages from security events)
- Divides by configurable `$Expected_Total_Packages` variable (default: 200)
- **Advantage:** Fast, single query, no complex joins
- **Limitation:** Requires manual configuration of expected total packages

### 2. Dedicated Supply Chain Tile (supply_component_score)
**Purpose:** Accurate, real-time package counting  
**Starting Point:** `fetch dt.entity.process_group_instance`  
**Supply Chain Calculation:**
```dql
fetch dt.entity.process_group_instance
| expand sw=contains[dt.entity.software_component]
| lookup software component details
| dedup name, version
| lookup vulnerabilities
| summarize total_packages=count(), vuln_packages=countIf(has_vuln)
```
- **Advantage:** Accurate real-time counts of all packages
- **Result:** Shows actual total packages and vulnerable packages

## Why Not Merge Them?
We attempted to merge these queries using DQL `lookup`, but encountered limitations:

1. **Nested Lookups:** The supply chain query requires multiple nested lookups (PGI → software component → vulnerabilities), which creates complex syntax that's hard to validate

2. **Performance:** Starting from security.events and joining to software components would require:
   - Expanding all affected process IDs
   - For each PID, expanding all software components
   - Joining with software component details
   - Deduplicating across all records
   - This could scan millions of records

3. **DQL Constraints:**
   - `lookup` requires explicit `sourceField`/`lookupField` matching
   - Cannot use `dedup` with `by:` parameter inside nested queries
   - `summarize by:{field}` without aggregation is invalid

## Current Implementation Benefits

✅ **Fast Main Score:** HRP overall score calculates quickly using estimated packages  
✅ **Accurate Supply Chain:** Dedicated tile shows real package counts  
✅ **Configurable:** Users can adjust `Expected_Total_Packages` for better estimation  
✅ **Topology Improved:** Main query now uses `related_entities` counts for accurate blast radius  
✅ **Maintainable:** Each query is clear and independently testable  

## Usage Recommendations

1. **For Quick Risk Assessment:** Use the main HRP Overall Score tile
   - Adjust `Expected_Total_Packages` variable to match your typical environment (e.g., 150-300)
   
2. **For Accurate Supply Chain Analysis:** Use the dedicated Supply Chain Component tile
   - Shows real-time counts
   - Accounts for all software components
   - Properly deduplicates packages

3. **For Detailed Investigation:** Use the "Vulnerabilities by Package" and "Detailed by PGI" tiles
   - Shows which packages are vulnerable
   - Breaks down risk per process group instance

## Query Validation
Both queries have been validated using Dynatrace MCP:
- ✅ Main HRP query: Valid syntax with improved topology calculation
- ✅ Supply Chain query: Valid syntax with real-time package counting

## Future Enhancements
If DQL adds support for:
- Nested `dedup` with `by:` parameter
- More flexible `lookup` with complex subqueries
- Cross-record set operations

Then we could fully integrate the supply chain calculation into the main HRP query.

## Files
- `/ASTRA_G/HRPv2_Dashboard.json` - Main dashboard with both approaches
- `/ASTRA_G/hrp_with_supply_chain.dql` - Experimental integrated query (for reference)
- `/ASTRA_G/SUPPLY_CHAIN_INTEGRATION.md` - This document
