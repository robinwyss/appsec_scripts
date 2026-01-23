#!/usr/bin/env python3
"""
ASTRA - Application Security Threat & Risk Assessment
Generates comprehensive risk assessment reports for Dynatrace-monitored applications.
"""

import sys
import os
import yaml
import json
import logging
from datetime import datetime
from argparse import ArgumentParser
from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path to import dynatrace_api
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import existing Dynatrace API wrapper
from dynatrace_api import DynatraceApi

# Try to import reportlab for PDF generation
try:
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    colors = None

# Configure logging (default to WARNING, will be adjusted based on config)
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('astra_report.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class AstraConfig:
    """Configuration loader and validator for ASTRA assessments."""
    
    def __init__(self, config_path: str):
        """Load configuration from YAML file."""
        self.config_path = config_path
        self.config = self._load_config()
        self._validate_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load YAML configuration file."""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            # Expand environment variables in config values
            config = self._expand_env_vars(config)
            logger.info(f"Configuration loaded from {self.config_path}")
            return config
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML configuration: {e}")
            sys.exit(1)
    
    def _expand_env_vars(self, config: Any) -> Any:
        """Recursively expand environment variables in config values."""
        if isinstance(config, dict):
            return {k: self._expand_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [self._expand_env_vars(item) for item in config]
        elif isinstance(config, str):
            # Expand ${VAR_NAME} or $VAR_NAME patterns
            import re
            def replacer(match):
                var_name = match.group(1) or match.group(2)
                value = os.environ.get(var_name)
                if value is None:
                    logger.error(f"Environment variable '{var_name}' is not set. "
                               f"Please set it: export {var_name}='your-value'")
                    sys.exit(1)
                return value
            # Match ${VAR} or $VAR patterns
            return re.sub(r'\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)', replacer, config)
        else:
            return config
    
    def _validate_config(self):
        """Validate required configuration fields."""
        required_fields = ['dynatrace', 'assessment', 'output']
        for field in required_fields:
            if field not in self.config:
                logger.error(f"Missing required configuration section: {field}")
                sys.exit(1)
        
        # Validate Dynatrace connection
        dt_config = self.config['dynatrace']
        if 'environment' not in dt_config or 'api_token' not in dt_config:
            logger.error("Missing Dynatrace environment or api_token")
            sys.exit(1)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot notation (e.g., 'dynatrace.environment')."""
        keys = key.split('.')
        value = self.config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value


class DataCollector:
    """Collects vulnerability and entity data from Dynatrace."""
    
    def __init__(self, api: DynatraceApi, config: AstraConfig):
        self.api = api
        self.config = config
        self.timeframe = config.get('assessment.timeframe', 'now-30d')
        self.max_workers = config.get('advanced.max_workers', 10)
        
    def collect_all_data(self) -> Dict[str, Any]:
        """Collect all required data for risk assessment."""
        logger.info("Starting data collection from Dynatrace...")
        
        # Get filter configuration
        filter_type = self.config.get('filters.type', 'process_group')
        filter_ids = self.config.get('filters.ids', [])
        
        # Determine filtered entity IDs based on filter type
        filtered_host_ids = None
        filtered_entity_ids = None
        
        if filter_ids:
            logger.info(f"Applying {filter_type} filter with {len(filter_ids)} IDs: {filter_ids}")
            
            if filter_type == 'host':
                filtered_host_ids = set(filter_ids)
                # Collect hosts first to get their process groups
                hosts = self._collect_hosts(filtered_host_ids)
                # Extract all process group IDs from filtered hosts
                filtered_entity_ids = set()
                for host in hosts:
                    if 'toRelationships' in host and 'isProcessOf' in host['toRelationships']:
                        for process in host['toRelationships']['isProcessOf']:
                            # Add process group instance ID
                            pgi_id = process['id']
                            filtered_entity_ids.add(pgi_id)
                            
                # Now get the process groups to also include their parent PROCESS_GROUP IDs
                process_groups = self._collect_process_groups(filtered_host_ids)
                for pg in process_groups:
                    # Add the PGI ID itself
                    filtered_entity_ids.add(pg.get('entityId'))
                    # Also add the parent PROCESS_GROUP if available
                    if 'fromRelationships' in pg and 'isInstanceOf' in pg['fromRelationships']:
                        for parent in pg['fromRelationships']['isInstanceOf']:
                            parent_pg_id = parent.get('id')
                            if parent_pg_id:
                                filtered_entity_ids.add(parent_pg_id)
                                logger.info(f"Added parent PROCESS_GROUP: {parent_pg_id}")
                    
                logger.info(f"Found {len(filtered_entity_ids)} entities (PGIs + parent PGs) on filtered hosts")
            elif filter_type == 'process_group':
                filtered_entity_ids = set(filter_ids)
                # Also collect process groups with this filter
                process_groups = self._collect_process_groups(None)  # Get all first
                # Filter to only specified process groups AND their instances
                filtered_pgs = []
                for pg in process_groups:
                    pg_id = pg.get('entityId')
                    # Check if this PG matches filter OR if it's an instance of a filtered PG
                    if pg_id in filtered_entity_ids:
                        filtered_pgs.append(pg)
                    elif 'fromRelationships' in pg and 'isInstanceOf' in pg['fromRelationships']:
                        for parent in pg['fromRelationships']['isInstanceOf']:
                            if parent.get('id') in filtered_entity_ids:
                                filtered_pgs.append(pg)
                                filtered_entity_ids.add(pg_id)  # Add PGI to filtered set
                                break
                logger.info(f"Filtered to {len(filtered_pgs)} process groups (from {len(process_groups)} total)")
            else:
                logger.warning(f"Unsupported filter type: {filter_type}. Collecting all data.")
        
        data = {
            'security_problems': self._collect_security_problems(filtered_entity_ids),
            'process_groups': filtered_pgs if filter_type == 'process_group' and filter_ids else self._collect_process_groups(filtered_host_ids),
            'hosts': self._collect_hosts(filtered_host_ids),
            'software_components': self._collect_software_components()
        }
        
        logger.info(f"Data collection complete: "
                   f"{len(data['security_problems'])} security problems, "
                   f"{len(data['process_groups'])} process groups, "
                   f"{len(data['hosts'])} hosts, "
                   f"{len(data['software_components'])} software components")
        
        # Apply exclusions for what-if analysis
        exclusion_stats = self._apply_exclusions(data)
        if exclusion_stats['excluded_count'] > 0:
            logger.warning(f"Applied exclusions: {exclusion_stats['excluded_count']} vulnerabilities excluded from {exclusion_stats['affected_pgis']} PGIs")
            data['exclusion_stats'] = exclusion_stats
        
        return data
    
    def _apply_exclusions(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply vulnerability exclusions for what-if analysis.
        
        Supports exclusions by:
        - PGI ID (pgi_id)
        - Process Group ID (pg_id)
        - Process Group Name contains match (pg_name_contains)
        
        Returns statistics about exclusions applied.
        """
        exclusions = self.config.get('exclusions.pgis', [])
        if not exclusions:
            return {'excluded_count': 0, 'affected_pgis': 0, 'details': []}
        
        # Build PGI to parent PG mapping and PG ID to name mapping
        pgi_to_pg_map = {}
        pg_id_to_name_map = {}
        pg_name_to_id_map = {}  # For reverse lookup by name
        
        for pg in data.get('process_groups', []):
            pgi_id = pg.get('entityId')
            pg_name = pg.get('displayName', '')
            
            # Map PG ID to name
            if pgi_id:
                pg_id_to_name_map[pgi_id] = pg_name
                pg_name_to_id_map[pg_name.lower()] = pgi_id
            
            # Map PGI to parent PG
            if 'fromRelationships' in pg and 'isInstanceOf' in pg['fromRelationships']:
                for parent in pg['fromRelationships']['isInstanceOf']:
                    parent_pg_id = parent.get('id')
                    if parent_pg_id:
                        pgi_to_pg_map[pgi_id] = parent_pg_id
                        # Also map parent PG ID to name if not already mapped
                        if parent_pg_id not in pg_id_to_name_map:
                            pg_id_to_name_map[parent_pg_id] = pg_name  # Use PGI name as fallback
        
        logger.debug(f"Built PGI->PG mapping: {len(pgi_to_pg_map)} entries")
        logger.debug(f"Built PG name mapping: {len(pg_id_to_name_map)} entries")
        
        # Build exclusion map: {pg_id: set(vulnerability_identifiers)}
        # Support multiple exclusion types: pgi_id, pg_id, pg_name_contains
        exclusion_map = {}
        
        for exclusion in exclusions:
            vuln_ids = exclusion.get('vulnerability_ids', exclusion.get('cves', []))
            if not vuln_ids:
                continue
            
            vuln_id_set = set(vuln_ids)
            
            # Type 1: PGI ID exclusion
            pgi_id = exclusion.get('pgi_id', '')
            if pgi_id:
                exclusion_map[pgi_id] = vuln_id_set
                # Also map the parent PG if this is a PGI
                if pgi_id in pgi_to_pg_map:
                    parent_pg = pgi_to_pg_map[pgi_id]
                    exclusion_map[parent_pg] = vuln_id_set
                    logger.debug(f"Mapped PGI {pgi_id} -> parent PG {parent_pg}")
            
            # Type 2: Direct PG ID exclusion
            pg_id = exclusion.get('pg_id', '')
            if pg_id:
                exclusion_map[pg_id] = vuln_id_set
                pg_name = pg_id_to_name_map.get(pg_id, 'Unknown')
                logger.debug(f"Added PG ID exclusion: {pg_id} ({pg_name})")
            
            # Type 3: PG Name contains match
            pg_name_contains = exclusion.get('pg_name_contains', '')
            if pg_name_contains:
                search_term = pg_name_contains.lower()
                matched_pgs = []
                for pg_id, pg_name in pg_id_to_name_map.items():
                    if search_term in pg_name.lower():
                        exclusion_map[pg_id] = vuln_id_set
                        matched_pgs.append(f"{pg_name} ({pg_id})")
                if matched_pgs:
                    logger.info(f"PG name contains '{pg_name_contains}' matched {len(matched_pgs)} process groups: {matched_pgs[:3]}..." if len(matched_pgs) > 3 else f"PG name contains '{pg_name_contains}' matched: {matched_pgs}")
        
        if not exclusion_map:
            return {'excluded_count': 0, 'affected_pgis': 0, 'details': []}
        
        logger.info(f"Applying exclusions for {len(exclusion_map)} PGI/PG IDs...")
        logger.debug(f"Exclusion map keys: {list(exclusion_map.keys())}")
        
        # Filter security problems
        original_count = len(data['security_problems'])
        excluded_vulns = []
        filtered_problems = []
        
        for problem in data['security_problems']:
            # Collect all possible identifiers for this vulnerability
            vuln_identifiers = set()
            
            # CVE IDs (array - can have multiple CVEs per vulnerability)
            cve_ids = problem.get('cveIds', [])
            if isinstance(cve_ids, list):
                vuln_identifiers.update(cve_ids)
            
            # External vulnerability ID (SNYK, etc.)
            if problem.get('externalVulnerabilityId'):
                vuln_identifiers.add(problem.get('externalVulnerabilityId'))
            
            # Dynatrace security problem ID
            if problem.get('securityProblemId'):
                vuln_identifiers.add(problem.get('securityProblemId'))
            
            # Display ID
            if problem.get('displayId'):
                vuln_identifiers.add(problem.get('displayId'))
            
            remediation_items = problem.get('remediationItems', [])
            
            # Debug logging for first few problems
            if len(filtered_problems) < 3:
                logger.debug(f"Problem {problem.get('securityProblemId')}: CVEs={cve_ids}, identifiers={vuln_identifiers}, remediation_items={[r.get('id') for r in remediation_items]}")
            
            # Check if this vulnerability should be excluded for any affected PGI
            exclude_problem = False
            matched_id = None
            for item in remediation_items:
                affected_pgi = item.get('id', '')
                if affected_pgi in exclusion_map:
                    # Check if any of the vulnerability identifiers match
                    matching_ids = vuln_identifiers & exclusion_map[affected_pgi]
                    if matching_ids:
                        exclude_problem = True
                        matched_id = list(matching_ids)[0]
                        pg_name = pg_id_to_name_map.get(affected_pgi, affected_pgi)
                        excluded_vulns.append({
                            'pgi_id': affected_pgi,
                            'pgi_name': pg_name,
                            'vulnerability_id': matched_id,
                            'title': problem.get('title', 'Unknown')
                        })
                        logger.info(f"Excluding {matched_id} ({problem.get('title', 'Unknown')[:50]}) from {pg_name} ({affected_pgi})")
                        break
            
            if not exclude_problem:
                filtered_problems.append(problem)
        
        # Update data with filtered problems
        data['security_problems'] = filtered_problems
        
        stats = {
            'excluded_count': original_count - len(filtered_problems),
            'affected_pgis': len(exclusion_map),
            'details': excluded_vulns
        }
        
        logger.info(f"Excluded {stats['excluded_count']} vulnerabilities from analysis")
        return stats
    
    def _fetch_security_problem_details(self, sec_problem: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch details for a single security problem (used in parallel execution)."""
        try:
            sp_id = sec_problem['securityProblemId']
            # Get detailed information
            details = self.api.getSecurityProblemDetails(sp_id)
            
            # Get remediation items (affected entities)
            remediation_items = self.api.getRemediationItems(sec_problem)
            details['remediationItems'] = remediation_items
            
            return details
        except Exception as e:
            logger.warning(f"Failed to enrich security problem {sec_problem['securityProblemId']}: {e}")
            return sec_problem
    
    def _collect_security_problems(self, filtered_entity_ids: set = None) -> List[Dict[str, Any]]:
        """Collect all security problems with details (parallel processing).
        
        Args:
            filtered_entity_ids: Optional set of entity IDs to filter security problems by
        """
        logger.info("Collecting security problems...")
        
        # Get all third-party security problems
        sec_problems = self.api.getThirdPartySecurityProblems()
        logger.info(f"Found {len(sec_problems)} security problems, fetching details in parallel...")
        
        # Enrich with details in parallel
        enriched_problems = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_sp = {executor.submit(self._fetch_security_problem_details, sp): sp 
                           for sp in sec_problems}
            
            # Collect results as they complete
            completed = 0
            for future in as_completed(future_to_sp):
                completed += 1
                if completed % 10 == 0 or completed == len(sec_problems):
                    logger.info(f"Processed {completed}/{len(sec_problems)} security problems")
                
                try:
                    details = future.result()
                    enriched_problems.append(details)
                except Exception as e:
                    sp = future_to_sp[future]
                    logger.error(f"Exception fetching security problem {sp['securityProblemId']}: {e}")
                    enriched_problems.append(sp)
        
        # Apply entity filtering if specified
        if filtered_entity_ids:
            logger.info(f"Applying entity filter to security problems...")
            logger.info(f"Filtering for entities: {filtered_entity_ids}")
            filtered_problems = []
            for problem in enriched_problems:
                # Check if any remediation item or related entity affects a filtered entity
                remediation_items = problem.get('remediationItems', [])
                
                # Check remediation items
                for item in remediation_items:
                    affected_entity = item.get('id', '')
                    if affected_entity in filtered_entity_ids:
                        logger.debug(f"Security problem {problem.get('securityProblemId')} matches via remediation item: {affected_entity}")
                        filtered_problems.append(problem)
                        break
                else:
                    # Also check relatedEntities field
                    related_entities = problem.get('relatedEntities', {})
                    if isinstance(related_entities, dict):
                        for entity_type, entities in related_entities.items():
                            if isinstance(entities, list):
                                for entity in entities:
                                    entity_id = entity.get('id', '') if isinstance(entity, dict) else entity
                                    if entity_id in filtered_entity_ids:
                                        logger.debug(f"Security problem {problem.get('securityProblemId')} matches via related entity: {entity_id}")
                                        filtered_problems.append(problem)
                                        break
                            if filtered_problems and filtered_problems[-1] == problem:
                                break
            
            logger.info(f"Filtered {len(enriched_problems)} problems down to {len(filtered_problems)} affecting specified entities")
            return filtered_problems
        
        logger.info(f"Successfully enriched {len(enriched_problems)} security problems")
        return enriched_problems
    
    def _collect_process_groups(self, filtered_host_ids: set = None) -> List[Dict[str, Any]]:
        """Collect process groups with properties and relationships.
        
        Args:
            filtered_host_ids: Optional set of host IDs to filter process groups by
        """
        logger.info("Collecting process groups...")
        
        # Get all hosts (which contain process relationships)
        hosts = self.api.getHosts()
        
        # Apply host filter if specified
        if filtered_host_ids:
            hosts = [h for h in hosts if h.get('entityId') in filtered_host_ids]
            logger.info(f"Filtered to {len(hosts)} hosts matching filter")
        
        # Extract unique process group instances
        pgi_ids = set()
        for host in hosts:
            if 'toRelationships' in host and 'isProcessOf' in host['toRelationships']:
                for process in host['toRelationships']['isProcessOf']:
                    pgi_ids.add(process['id'])
        
        logger.info(f"Found {len(pgi_ids)} unique process group instances")
        
        # Get detailed process information
        if pgi_ids:
            pgi_list = [{'id': pgi_id} for pgi_id in pgi_ids]
            processes = self.api.getProcessesWithDetails(pgi_list)
            return processes
        
        return []
    
    def _collect_hosts(self, filtered_host_ids: set = None) -> List[Dict[str, Any]]:
        """Collect host information.
        
        Args:
            filtered_host_ids: Optional set of host IDs to filter by
        """
        logger.info("Collecting hosts...")
        hosts = self.api.getHosts()
        
        if filtered_host_ids:
            hosts = [h for h in hosts if h.get('entityId') in filtered_host_ids]
            logger.info(f"Filtered to {len(hosts)} hosts matching filter")
        
        return hosts
    
    def _collect_software_components(self) -> List[Dict[str, Any]]:
        """Collect all SOFTWARE_COMPONENT entities from Dynatrace."""
        logger.info("Collecting software components...")
        try:
            # Query for all SOFTWARE_COMPONENT entities
            endpoint = '/api/v2/entities?entitySelector=type(SOFTWARE_COMPONENT)&fields=properties.packageName,properties.softwareComponentFileName,properties.softwareComponentShortName,properties.softwareComponentType'
            response = self.api.queryApi(endpoint)
            components = response.get('entities', [])
            logger.info(f"Found {len(components)} software components")
            return components
        except Exception as e:
            logger.warning(f"Failed to collect software components: {e}")
            return []


class RiskCalculator:
    """Calculates risk scores using CWRS or REI methodology."""
    
    def __init__(self, config: AstraConfig):
        self.config = config
        self.risk_model = config.get('assessment.risk_model', 'CWRS').upper()
        # Conservative weights: emphasis on exploitability and vulnerability severity
        # Adjusted to err on the side of caution
        self.weights = {
            'vulnerability': config.get('scoring.vulnerability_weight', 35),     # Reduced from 40 to balance
            'exploitability': config.get('scoring.exploitability_weight', 30),  # Increased from 25 - active threats priority
            'exposure': config.get('scoring.exposure_weight', 20),              # Same - attack surface matters
            'criticality': config.get('scoring.criticality_weight', 15)         # Same - infrastructure context
        }
        
    def calculate_overall_risk(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall application risk score using HRP v2.0 model."""
        logger.info("Calculating overall risk score using HRP2 model...")
        return self._calculate_hrp_v2_risk(data)
    
    # ========== Deprecated Risk Models Removed ==========
    # CWRS, REI, and HRP v1 have been deprecated in favor of HRP v2.0
    
    # ========== HRP v2.0 (Holistic Risk Posture v2) Methods ==========
    
    def _calculate_hrp_v2_risk(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate HRP v2.0 - 0-100 scale with square root dampening for high sensitivity."""
        import math
        from datetime import datetime
        
        vulnerabilities = data['security_problems']
        
        # Get v2 config with defaults
        hrp_v2_config = self.config.get('hrp_v2', {})
        vuln_weight = hrp_v2_config.get('vulnerability_weight', 0.60)
        supply_weight = hrp_v2_config.get('supply_chain_weight', 0.20)
        topo_weight = hrp_v2_config.get('topology_weight', 0.15)
        aging_weight = hrp_v2_config.get('aging_weight', 0.05)
        
        # Component 1: Vulnerability Severity with power dampening
        vuln_score = self._calculate_hrp_v2_vulnerabilities(vulnerabilities, hrp_v2_config)
        
        # Component 2: Supply Chain (vulnerable libraries ratio)
        supply_score = self._calculate_hrp_v2_supply_chain(vulnerabilities, data, hrp_v2_config)
        
        # Component 3: Topology Risk (blast radius, connectivity, critical path)
        topology_score = self._calculate_hrp_v2_topology(vulnerabilities, data, hrp_v2_config)
        
        # Component 4: Aging Factor
        aging_score = self._calculate_hrp_v2_aging(vulnerabilities, hrp_v2_config)
        
        # Calculate weighted total (0-100 scale)
        hrp_score = (vuln_weight * vuln_score) + (supply_weight * supply_score) + \
                    (topo_weight * topology_score) + (aging_weight * aging_score)
        hrp_score = min(max(hrp_score, 0), 100)
        
        risk_rating = self._get_risk_rating_hrp_v2(hrp_score)
        
        return {
            'score': round(hrp_score, 2),
            'rating': risk_rating,
            'model': 'HRP2',
            'components': {
                'vulnerability_score': round(vuln_score, 2),
                'supply_chain_score': round(supply_score, 2),
                'topology_score': round(topology_score, 2),
                'aging_score': round(aging_score, 2)
            }
        }
    
    def calculate_remediation_priorities(self, data: Dict[str, Any], current_overall_risk: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Calculate top 10 vulnerabilities by remediation impact using HRP v2.0.
        
        Returns list of vulnerabilities sorted by impact (score improvement if remediated).
        Uses actual recalculation for accurate impact assessment.
        """
        import copy
        vulnerabilities = data['security_problems']
        priorities = []
        current_score = current_overall_risk['score']
        
        logger.info(f"Calculating remediation impact for {len(vulnerabilities)} vulnerabilities...")
        
        for idx, vuln in enumerate(vulnerabilities):
            # Create deep copy of data without this vulnerability
            temp_data = copy.deepcopy(data)
            temp_data['security_problems'] = [
                v for v in temp_data['security_problems'] 
                if v.get('securityProblemId') != vuln.get('securityProblemId')
            ]
            
            # Recalculate score without this vulnerability
            try:
                temp_risk = self.calculate_overall_risk(temp_data)
                temp_score = temp_risk['score']
                
                # Calculate impact (how much score improves)
                impact = current_score - temp_score
            except Exception as e:
                logger.warning(f"Failed to calculate impact for vulnerability {vuln.get('securityProblemId')}: {e}")
                impact = 0
            
            # Get affected PGIs for display
            affected_pgis = self._get_affected_pgis(vuln, data)
            
            risk_assessment = vuln.get('riskAssessment', {})
            if not isinstance(risk_assessment, dict):
                risk_assessment = {}
            
            davis_score = risk_assessment.get('riskScore', risk_assessment.get('baseRiskScore', 0))
            
            priorities.append({
                'vulnerability_id': vuln.get('securityProblemId'),
                'title': vuln.get('title', 'Unknown'),
                'cveIds': vuln.get('cveIds', []),
                'externalVulnerabilityId': vuln.get('externalVulnerabilityId'),
                'displayId': vuln.get('displayId'),
                'securityProblemId': vuln.get('securityProblemId'),
                'severity': risk_assessment.get('riskLevel', 'UNKNOWN'),
                'davis_score': davis_score,
                'impact': round(impact, 3),
                'affected_pgis': affected_pgis,
                'affected_pgi_count': len(affected_pgis)
            })
            
            # Log progress every 20 vulnerabilities
            if (idx + 1) % 20 == 0:
                logger.info(f"  Processed {idx + 1}/{len(vulnerabilities)} vulnerabilities...")
        
        # Sort by impact (descending) and return top 10
        priorities.sort(key=lambda x: x['impact'], reverse=True)
        return priorities[:10]
    
    def _get_affected_pgis(self, vuln: Dict[str, Any], data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract affected PGIs from a vulnerability."""
        affected_pgis = []
        related_entities = vuln.get('relatedEntities', {})
        
        for entity_type in ['services', 'hosts', 'kubernetesWorkloads', 'kubernetesClusters']:
            entities_list = related_entities.get(entity_type, [])
            for related_entity in entities_list:
                affected = related_entity.get('affectedEntities', [])
                for entity_id in affected:
                    if 'PROCESS_GROUP_INSTANCE' in entity_id:
                        # Find entity name
                        entity_name = None
                        for pg in data.get('process_groups', []):
                            if pg.get('entityId') == entity_id:
                                entity_name = pg.get('displayName', entity_id)
                                break
                        affected_pgis.append({
                            'id': entity_id,
                            'name': entity_name or entity_id
                        })
        
        return affected_pgis
    
    def calculate_entity_risk(self, entity: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate HRP v2.0 risk score for a specific entity."""
        entity_id = entity.get('entityId')
        entity_name = entity.get('displayName', entity_id)
        
        # Filter vulnerabilities affecting this entity
        entity_vulns = []
        for v in vulnerabilities:
            related_entities = v.get('relatedEntities', {})
            
            # Check all entity types in relatedEntities
            for entity_type in ['services', 'hosts', 'kubernetesWorkloads', 'kubernetesClusters']:
                entities_list = related_entities.get(entity_type, [])
                for related_entity in entities_list:
                    affected = related_entity.get('affectedEntities', [])
                    if entity_id in affected:
                        entity_vulns.append(v)
                        break
                if v in entity_vulns:
                    break
        
        if not entity_vulns:
            return {
                'entity_id': entity_id,
                'entity_name': entity_name,
                'risk_score': 0,
                'risk_rating': 'NONE',
                'vulnerability_count': 0
            }
        
        # Create minimal data structure for HRP v2 calculation
        entity_data = {
            'security_problems': entity_vulns,
            'process_groups': [entity] if 'PROCESS_GROUP' in entity_id else [],
            'hosts': []
        }
        
        # Calculate HRP v2 for this entity
        hrp_result = self._calculate_hrp_v2_risk(entity_data)
        
        return {
            'entity_id': entity_id,
            'entity_name': entity_name,
            'entity_type': entity.get('type', 'UNKNOWN'),
            'risk_score': hrp_result['score'],
            'risk_rating': hrp_result['rating'],
            'vulnerability_count': len(entity_vulns),
            'vulnerabilities': entity_vulns,
            'components': hrp_result['components']
        }
    
    def _calculate_hrp_v2_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]], 
                                          config: Dict[str, Any]) -> float:
        """Calculate vulnerability component using square root dampening (0-100 scale)."""
        import math
        
        # Get config parameters
        max_score = config.get('max_theoretical_score', 500)
        exploit_mult = config.get('exploitability_multiplier', 2.0)
        cve_mult = config.get('cve_multiplier', 1.2)
        dampening = config.get('dampening_function', 'sqrt')
        
        weighted_sum = 0
        
        for vuln in vulnerabilities:
            risk_assessment = vuln.get('riskAssessment', {})
            if not isinstance(risk_assessment, dict):
                continue
            
            # Get Davis Security Score
            davis_score = risk_assessment.get('riskScore', 0)
            if davis_score == 0:
                davis_score = risk_assessment.get('baseRiskScore', 0)
            
            if davis_score == 0:
                severity = risk_assessment.get('riskLevel', 'LOW')
                severity_map = {'CRITICAL': 9.5, 'HIGH': 7.5, 'MEDIUM': 5.0, 'LOW': 2.0}
                davis_score = severity_map.get(severity, 0)
            
            # Normalize Davis score to base value
            if davis_score >= 9.0:
                base_value = 10.0
            elif davis_score >= 7.0:
                base_value = 7.5
            elif davis_score >= 4.0:
                base_value = 4.0
            elif davis_score > 0:
                base_value = 1.5
            else:
                base_value = 0
            
            # Apply exploitability multiplier
            exploit_factor = 1.0
            if vuln.get('hasPublicExploit', False):
                exploit_factor = exploit_mult
            elif vuln.get('vulnerableFunctionInUse', False):
                exploit_factor = 1.5
            
            # Apply CVE multiplier
            cve_factor = cve_mult if vuln.get('cveId') or vuln.get('vulnerabilityId', '').startswith('CVE-') else 1.0
            
            # Add weighted contribution
            weighted_sum += base_value * exploit_factor * cve_factor
        
        # Apply adaptive dampening function
        if dampening == 'sqrt':
            # Square root dampening with adaptive scaling for extreme cases
            if weighted_sum <= max_score:
                # Pure square root for normal range
                score = 100 * math.sqrt(weighted_sum) / math.sqrt(max_score)
            else:
                # Hybrid: sqrt up to max_score, then logarithmic
                base = 100  # Score at transition point
                excess = weighted_sum - max_score
                # Logarithmic growth for excess (caps at +20)
                log_add = 20 * math.log10(1 + excess) / math.log10(1 + 9500)
                score = min(base + log_add, 120)
        elif dampening == 'log10':
            # Logarithmic dampening (fallback option)
            score = 100 * math.log10(1 + weighted_sum) / math.log10(1 + max_score)
        elif dampening == 'power':
            # Configurable power dampening
            exponent = config.get('dampening_exponent', 0.5)
            score = 100 * (weighted_sum ** exponent) / (max_score ** exponent)
        else:
            # No dampening (linear)
            score = min(100, (weighted_sum / max_score) * 100)
        
        return min(score, 100)
    
    def _calculate_hrp_v2_supply_chain(self, vulnerabilities: List[Dict[str, Any]], 
                                        data: Dict[str, Any], config: Dict[str, Any]) -> float:
        """
        Calculate supply chain risk based on vulnerable library ratio (0-100 scale).
        High importance component focusing on software composition analysis.
        """
        import math
        
        supply_power = config.get('supply_chain_power', 0.7)
        
        vulnerable_libraries = set()
        total_libraries = set()
        
        # Track vulnerable libraries from packageName and technology
        for vuln in vulnerabilities:
            package_name = vuln.get('packageName')
            technology = vuln.get('technology', 'UNKNOWN')
            
            if package_name:
                # Create library ID from technology and package name
                lib_id = f"{technology}_{package_name}"
                vulnerable_libraries.add(lib_id)
        
        # Count total software components from SOFTWARE_COMPONENT entities
        for component in data.get('software_components', []):
            properties = component.get('properties', {})
            package_name = properties.get('packageName')
            comp_type = properties.get('softwareComponentType', 'UNKNOWN')
            
            if package_name:
                lib_id = f"{comp_type}_{package_name}"
                total_libraries.add(lib_id)
            
            # Also try other name fields
            for name_field in ['softwareComponentShortName', 'softwareComponentFileName']:
                name = properties.get(name_field)
                if name:
                    lib_id = f"{comp_type}_{name}"
                    total_libraries.add(lib_id)
        
        # Calculate vulnerable ratio with power-law scaling
        if len(total_libraries) > 0:
            vuln_ratio = len(vulnerable_libraries) / len(total_libraries)
            supply_score = 100 * (vuln_ratio ** supply_power)
        else:
            supply_score = 0
        
        return min(supply_score, 100)
    
    def _calculate_hrp_v2_topology(self, vulnerabilities: List[Dict[str, Any]], 
                                    data: Dict[str, Any], config: Dict[str, Any]) -> float:
        """
        Calculate topology risk with exponential and power-law functions (0-100 scale).
        
        Includes:
        - Blast radius (affected entities count)
        - Connectivity depth (service dependency chains)
        - Critical path analysis (databases, services, K8s)
        
        Note: Supply chain is now a separate high-importance component
        """
        import math
        
        # Get config parameters
        blast_decay = config.get('blast_radius_decay', 0.05)
        enable_connectivity = config.get('enable_connectivity_analysis', True)
        
        # Track affected entities and relationships
        affected_entities = set()
        entity_relationships = {}  # Graph: entity_id -> [connected_entity_ids]
        vulnerable_entity_types = {}  # entity_id -> type (HOST, PROCESS, etc.)
        
        for vuln in vulnerabilities:
            # Count affected entities from remediation items
            remediation_items = vuln.get('remediationItems', [])
            for item in remediation_items:
                entity_id = item.get('id')
                entity_type = item.get('type', 'UNKNOWN')
                if entity_id:
                    affected_entities.add(entity_id)
                    vulnerable_entity_types[entity_id] = entity_type
        
        # Build connectivity graph from Dynatrace relationships
        if enable_connectivity:
            # Process group relationships (isInstanceOf, calls, etc.)
            for pg in data.get('process_groups', []):
                pg_id = pg.get('entityId')
                if pg_id:
                    entity_relationships[pg_id] = []
                    
                    # Parent relationships (isInstanceOf)
                    if 'fromRelationships' in pg and 'isInstanceOf' in pg['fromRelationships']:
                        for parent in pg['fromRelationships']['isInstanceOf']:
                            parent_id = parent.get('id')
                            if parent_id:
                                entity_relationships[pg_id].append(parent_id)
                    
                    # Service calls (if available)
                    if 'toRelationships' in pg:
                        for rel_type, targets in pg['toRelationships'].items():
                            if rel_type in ['calls', 'runsOn', 'isProcessOf']:
                                for target in targets:
                                    target_id = target.get('id')
                                    if target_id:
                                        entity_relationships[pg_id].append(target_id)
            
            # Host relationships
            for host in data.get('hosts', []):
                host_id = host.get('entityId')
                if host_id:
                    entity_relationships[host_id] = []
                    
                    # Process relationships (isProcessOf)
                    if 'toRelationships' in host and 'isProcessOf' in host['toRelationships']:
                        for process in host['toRelationships']['isProcessOf']:
                            process_id = process.get('id')
                            if process_id:
                                entity_relationships[host_id].append(process_id)
        
        # === Component 1: Blast Radius (entity count) ===
        entity_count = len(affected_entities)
        blast_score = 100 * (1 - math.exp(-blast_decay * entity_count))
        
        # === Component 2: Connectivity Depth (transitive risk) ===
        connectivity_score = 0
        if enable_connectivity and entity_relationships:
            # Calculate transitive risk using BFS from vulnerable entities
            connected_entities = self._calculate_transitive_risk(
                affected_entities, 
                entity_relationships, 
                max_depth=3  # Look 3 hops away
            )
            
            # Score based on how many additional entities are at risk
            transitive_count = len(connected_entities) - len(affected_entities)
            if transitive_count > 0:
                # Power-law: lots of connections = exponentially worse
                connectivity_score = min(100, 100 * (transitive_count / 50) ** 0.6)
        
        # === Component 3: Critical Path Analysis (database/network exposure) ===
        critical_path_score = 0
        if enable_connectivity:
            # Check if vulnerable entities are "critical" types
            critical_types = {'DATABASE_CONNECTION_FAILURE', 'SERVICE', 'APPLICATION', 'KUBERNETES_CLUSTER'}
            critical_count = sum(1 for etype in vulnerable_entity_types.values() 
                               if any(crit in etype for crit in critical_types))
            
            if critical_count > 0:
                critical_path_score = min(100, (critical_count / len(affected_entities)) * 100)
        
        # === Weighted Topology Score ===
        # Topology now excludes supply chain (it's a separate top-level component)
        if enable_connectivity:
            # With connectivity: 40% blast + 35% connectivity + 25% critical
            topology_score = (0.40 * blast_score + 
                            0.35 * connectivity_score +
                            0.25 * critical_path_score)
        else:
            # Without connectivity: 100% blast radius only
            topology_score = blast_score
        
        return min(topology_score, 100)
    
    def _calculate_transitive_risk(self, vulnerable_entities: set, 
                                   entity_graph: dict, max_depth: int = 3) -> set:
        """
        Calculate transitive risk using BFS to find all entities connected to vulnerable ones.
        
        Args:
            vulnerable_entities: Set of entity IDs with vulnerabilities
            entity_graph: Dictionary mapping entity_id -> [connected_entity_ids]
            max_depth: Maximum hops to traverse (default 3)
        
        Returns:
            Set of all entities within max_depth hops of vulnerable entities
        """
        from collections import deque
        
        visited = set()
        queue = deque([(entity, 0) for entity in vulnerable_entities])  # (entity_id, depth)
        
        while queue:
            entity_id, depth = queue.popleft()
            
            if entity_id in visited or depth > max_depth:
                continue
            
            visited.add(entity_id)
            
            # Add connected entities to queue
            if entity_id in entity_graph:
                for connected_id in entity_graph[entity_id]:
                    if connected_id not in visited:
                        queue.append((connected_id, depth + 1))
        
        return visited
    
    def _calculate_hrp_v2_aging(self, vulnerabilities: List[Dict[str, Any]], 
                                config: Dict[str, Any]) -> float:
        """Calculate continuous aging factor (0-100 scale)."""
        from datetime import datetime
        import math
        
        # Get config parameter
        aging_scale = config.get('aging_scale_factor', 0.5)
        
        score = 0
        current_time = datetime.now()
        
        for vuln in vulnerabilities:
            # Get first seen timestamp
            first_seen = vuln.get('firstSeenTimestamp')
            if not first_seen:
                continue
            
            try:
                if isinstance(first_seen, (int, float)):
                    first_seen_dt = datetime.fromtimestamp(first_seen / 1000)
                else:
                    first_seen_dt = datetime.fromisoformat(str(first_seen).replace('Z', '+00:00'))
                
                age_days = (current_time - first_seen_dt).days
                
                risk_assessment = vuln.get('riskAssessment', {})
                if isinstance(risk_assessment, dict):
                    severity = risk_assessment.get('riskLevel', 'LOW')
                    
                    # Continuous aging calculation
                    severity_weights = {'CRITICAL': 15, 'HIGH': 8, 'MEDIUM': 3, 'LOW': 1}
                    severity_weight = severity_weights.get(severity, 1)
                    
                    # Age penalty: (age_days / 365) * severity_weight * scaling_factor
                    age_penalty = (age_days / 365) * severity_weight * aging_scale
                    score += age_penalty
                    
            except Exception as e:
                logger.debug(f"Error calculating age for vulnerability: {e}")
                continue
        
        return min(score, 100)
    
    def _calculate_hrp_critical_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate critical vulnerability component using Davis Security Score (0-100 points)."""
        score = 0
        
        for vuln in vulnerabilities:
            risk_assessment = vuln.get('riskAssessment', {})
            if not isinstance(risk_assessment, dict):
                continue
            
            # Get Davis Security Score
            davis_score = risk_assessment.get('riskScore', 0)
            if davis_score == 0:
                davis_score = risk_assessment.get('baseRiskScore', 0)
            
            if davis_score == 0:
                severity = risk_assessment.get('riskLevel', 'LOW')
                severity_map = {'CRITICAL': 9.5, 'HIGH': 7.5, 'MEDIUM': 5.0, 'LOW': 2.0}
                davis_score = severity_map.get(severity, 0)
            
            # Weight by Davis Score - higher scores contribute more
            if davis_score >= 9.0:
                score += 15  # CRITICAL range
            elif davis_score >= 7.0:
                score += 8   # HIGH range
            elif davis_score >= 4.0:
                score += 3   # MEDIUM range
            elif davis_score > 0:
                score += 1   # LOW range
        
        return min(score, 100)
    
    def _calculate_hrp_topology_risk(self, vulnerabilities: List[Dict[str, Any]], 
                                      data: Dict[str, Any]) -> float:
        """Calculate topology/supply chain risk based on affected entities and library dependencies (0-100 points)."""
        score = 0
        
        # Track affected entities (blast radius)
        affected_entities = set()
        vulnerable_libraries = set()
        total_libraries = set()
        
        for vuln in vulnerabilities:
            # Count affected entities from remediation items
            remediation_items = vuln.get('remediationItems', [])
            for item in remediation_items:
                entity_id = item.get('id')
                if entity_id:
                    affected_entities.add(entity_id)
            
            # Track vulnerable components (supply chain risk)
            if 'vulnerableComponents' in vuln:
                for comp in vuln['vulnerableComponents']:
                    comp_id = comp.get('id')
                    if comp_id:
                        vulnerable_libraries.add(comp_id)
                        total_libraries.add(comp_id)
        
        # Also count total software components from process groups
        for pg in data.get('process_groups', []):
            if 'softwareTechnologies' in pg:
                for tech in pg['softwareTechnologies']:
                    tech_id = tech.get('type', '') + '_' + tech.get('version', '')
                    total_libraries.add(tech_id)
        
        # Score based on blast radius (affected entities)
        entity_count = len(affected_entities)
        if entity_count >= 20:
            score += 40
        elif entity_count >= 10:
            score += 30
        elif entity_count >= 5:
            score += 20
        elif entity_count > 0:
            score += 10
        
        # Score based on supply chain risk (vulnerable library ratio)
        if len(total_libraries) > 0:
            vuln_ratio = len(vulnerable_libraries) / len(total_libraries)
            score += vuln_ratio * 60  # Up to 60 points for 100% vulnerable
        
        return min(score, 100)
    
    def _calculate_hrp_aging_factor(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate remediation velocity / aging factor (0-100 points)."""
        from datetime import datetime
        
        score = 0
        current_time = datetime.now()
        
        for vuln in vulnerabilities:
            # Get first seen timestamp
            first_seen = vuln.get('firstSeenTimestamp')
            if not first_seen:
                continue
            
            try:
                if isinstance(first_seen, (int, float)):
                    first_seen_dt = datetime.fromtimestamp(first_seen / 1000)
                else:
                    first_seen_dt = datetime.fromisoformat(str(first_seen).replace('Z', '+00:00'))
                
                age_days = (current_time - first_seen_dt).days
                
                risk_assessment = vuln.get('riskAssessment', {})
                if isinstance(risk_assessment, dict):
                    severity = risk_assessment.get('riskLevel', 'LOW')
                    
                    # Aging penalty increases with severity and time
                    if severity == 'CRITICAL':
                        if age_days > 90:
                            score += 10
                        elif age_days > 30:
                            score += 5
                        elif age_days > 7:
                            score += 2
                    elif severity == 'HIGH':
                        if age_days > 180:
                            score += 8
                        elif age_days > 90:
                            score += 4
                        elif age_days > 30:
                            score += 2
                    elif severity == 'MEDIUM':
                        if age_days > 365:
                            score += 4
                        elif age_days > 180:
                            score += 2
            except Exception as e:
                logger.debug(f"Error calculating age for vulnerability: {e}")
                continue
        
        return min(score, 100)
    
    def _get_risk_rating_hrp(self, hrp_score: float) -> str:
        """Convert HRP v1 score (1-10) to rating."""
        if hrp_score >= 8.5:
            return 'CRITICAL'
        elif hrp_score >= 6.5:
            return 'HIGH'
        elif hrp_score >= 4.0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_risk_rating_hrp_v2(self, hrp_score: float) -> str:
        """Convert HRP v2 score (0-100) to rating."""
        if hrp_score >= 85.0:
            return 'CRITICAL'
        elif hrp_score >= 65.0:
            return 'HIGH'
        elif hrp_score >= 40.0:
            return 'MEDIUM'
        elif hrp_score >= 20.0:
            return 'LOW'
        else:
            return 'MINIMAL'


class JsonExporter:
    """Exports assessment results to JSON format."""
    
    def __init__(self, config: AstraConfig):
        self.config = config
        
    def export(self, data: Dict[str, Any], overall_risk: Dict[str, Any], 
               entity_risks: List[Dict[str, Any]], remediation_priorities: List[Dict[str, Any]] = None) -> str:
        """Export complete assessment to JSON file."""
        timestamp = datetime.now()
        report_id = f"astra_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        
        report = {
            'metadata': {
                'report_id': report_id,
                'generated_at': timestamp.isoformat(),
                'timeframe': self.config.get('assessment.timeframe'),
                'risk_model': self.config.get('assessment.risk_model', 'CWRS'),
                'astra_version': '1.5.0',
                'host_count': len(data.get('hosts', [])),
                'tenant_url': self.config.get('dynatrace.environment', ''),
                'exclusions_applied': data.get('exclusion_stats', {}).get('excluded_count', 0) > 0
            },
            'config': {
                'filters': self.config.get('filters', {}),
                'scoring': self.config.get('scoring', {}),
                'exclusions': self.config.get('exclusions', {})
            },
            'overall_risk': overall_risk,
            'entities': entity_risks,
            'remediation_priorities': remediation_priorities or [],
            'summary': self._generate_summary(data, entity_risks),
            'exclusion_stats': data.get('exclusion_stats', {'excluded_count': 0, 'affected_pgis': 0, 'details': []})
        }
        
        # Create output directory if it doesn't exist
        output_path = Path(self.config.get('output.json_path', './reports'))
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Write JSON file
        filename_prefix = self.config.get('output.filename_prefix', 'astra_report')
        json_file = output_path / f"{filename_prefix}_{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"JSON report saved to {json_file}")
        return str(json_file)
    
    def _generate_summary(self, data: Dict[str, Any], entity_risks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics."""
        vulnerabilities = data['security_problems']
        
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('riskAssessment', {}).get('riskLevel', 'LOW')
            severity_count[severity] = severity_count.get(severity, 0) + 1
        
        return {
            'total_entities': len(entity_risks),
            'total_vulnerabilities': len(vulnerabilities),
            'by_severity': severity_count,
            'high_risk_entities': len([e for e in entity_risks if e['risk_rating'] in ['HIGH', 'CRITICAL']])
        }


class PdfGenerator:
    """Wrapper for beautiful PDF report generation."""
    
    def __init__(self, config: AstraConfig):
        self.config = config
        
    def generate(self, json_file: str) -> str:
        """Generate beautiful PDF report from JSON data."""
        if not REPORTLAB_AVAILABLE:
            logger.warning("reportlab library not installed. Install with: pip install reportlab")
            logger.info("Skipping PDF generation, JSON report is available")
            return ""
        
        # Import and use the beautiful PDF generator
        try:
            from pdf_generator_beautiful import BeautifulPDFGenerator
            generator = BeautifulPDFGenerator(self.config)
            pdf_file = generator.generate(json_file)
            logger.info(f"Generated beautiful PDF report: {pdf_file}")
            return pdf_file
        except ImportError as e:
            logger.error(f"Failed to import beautiful PDF generator: {e}")
            logger.info("Falling back to basic PDF generation")
            return self._generate_basic_pdf(json_file)
        except Exception as e:
            logger.error(f"Failed to generate beautiful PDF: {e}", exc_info=True)
            logger.info("Falling back to basic PDF generation")
            return self._generate_basic_pdf(json_file)
    
    def _generate_basic_pdf(self, json_file: str) -> str:
        """Fallback: Generate basic PDF if beautiful generator fails."""
        import json
        from pathlib import Path
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        
        # Load JSON data
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Create output
        output_path = Path(self.config.get('output.pdf_path', './reports'))
        output_path.mkdir(parents=True, exist_ok=True)
        report_id = data['metadata']['report_id']
        pdf_file = output_path / f"{report_id}_basic.pdf"
        
        doc = SimpleDocTemplate(str(pdf_file), pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Simple title
        story.append(Paragraph("ASTRA Risk Assessment Report", styles['Title']))
        story.append(Spacer(1, 0.5*inch))
        
        # Basic info
        overall_risk = data['overall_risk']
        risk_model = overall_risk.get('model', 'CWRS')
        scale_max = "10" if risk_model == 'REI' else "100"
        
        story.append(Paragraph(f"Risk Score: {overall_risk['score']}/{scale_max}", styles['Heading1']))
        story.append(Paragraph(f"Rating: {overall_risk['rating']}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Summary
        summary = data['summary']
        story.append(Paragraph(f"Total Vulnerabilities: {summary['total_vulnerabilities']}", styles['Normal']))
        story.append(Paragraph(f"Total Entities: {summary['total_entities']}", styles['Normal']))
        story.append(Paragraph(f"High Risk Entities: {summary['high_risk_entities']}", styles['Normal']))
        
        doc.build(story)
        logger.info(f"Generated basic PDF report: {pdf_file}")
        return str(pdf_file)




def run_assessment(config: AstraConfig) -> str:
    """Execute risk assessment and generate reports.
    
    Args:
        config: Loaded ASTRA configuration
        
    Returns:
        Path to generated JSON report
    """
    logger.info("Running Risk Assessment")
    
    # Initialize Dynatrace API
    api = DynatraceApi(
        tenant=config.get('dynatrace.environment'),
        apiToken=config.get('dynatrace.api_token'),
        verifySSL=config.get('dynatrace.verify_ssl', True)
    )
    
    # Collect data
    collector = DataCollector(api, config)
    data = collector.collect_all_data()
    
    # Calculate risks
    calculator = RiskCalculator(config)
    overall_risk = calculator.calculate_overall_risk(data)
    
    # Log overall risk (HRP v2.0: 0-100 scale)
    logger.info(f"Overall Risk Score: {overall_risk['score']}/100 ({overall_risk['rating']})")
    
    # Calculate entity-level risks
    # Note: Only calculates for process groups in data['process_groups'], which are already filtered
    entity_risks = []
    for pg in data['process_groups']:
        entity_risk = calculator.calculate_entity_risk(pg, data['security_problems'])
        if entity_risk['vulnerability_count'] > 0:
            entity_risks.append(entity_risk)
    
    logger.info(f"Analyzed {len(entity_risks)} entities with vulnerabilities")
    
    # Calculate remediation priorities
    logger.info("Calculating top 10 remediation priorities by impact...")
    remediation_priorities = calculator.calculate_remediation_priorities(data, overall_risk)
    logger.info(f"Identified {len(remediation_priorities)} high-impact vulnerabilities")
    
    # Export JSON
    json_exporter = JsonExporter(config)
    json_file = json_exporter.export(data, overall_risk, entity_risks, remediation_priorities)
    
    # Generate PDF
    pdf_generator = PdfGenerator(config)
    pdf_file = pdf_generator.generate(json_file)
    
    logger.info("="*80)
    logger.info("Assessment Complete!")
    logger.info(f"JSON Report: {json_file}")
    if pdf_file:
        logger.info(f"PDF Report: {pdf_file}")
    logger.info("="*80)
    
    return json_file


def run_dampening_optimization(config: AstraConfig, report_json_path: str) -> None:
    """Execute HRP v2.0 dampening parameter optimization.
    
    Args:
        config: Loaded ASTRA configuration
        report_json_path: Path to JSON report from assessment
    """
    from dampening_optimizer import DampeningOptimizer
    
    logger.info("="*80)
    logger.info("HRP v2.0 - Auto-Dampening Optimization")
    logger.info("="*80)
    
    # HRP v2.0 is the only model now, no check needed
    
    # Load report data
    try:
        with open(report_json_path, 'r') as f:
            report_data = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load report data: {e}")
        return
    
    # Initialize calculator (needed for simulation)
    calculator = RiskCalculator(config)
    
    # Run optimization
    optimizer = DampeningOptimizer(report_data, config, calculator)
    
    # Analyze environment
    logger.info("Analyzing environment complexity...")
    env_analysis = optimizer.analyze_environment()
    logger.info(f"  Total vulnerabilities: {env_analysis['total_vulnerabilities']}")
    logger.info(f"  Current score: {env_analysis['current_score']:.2f}")
    logger.info(f"  Saturated components: {len(env_analysis['saturated_components'])}")
    
    # Find optimal parameters
    logger.info("")
    logger.info("Starting parameter grid search (25 combinations)...")
    result = optimizer.find_optimal_params()
    
    # Generate and display report
    logger.info("")
    report = optimizer.generate_report(result)
    
    # Check verbose logging setting
    verbose = config.get('advanced.verbose_logging', False)
    
    if verbose:
        # Show full report and prompt for confirmation
        print("\n" + report)
        print("\nApply these parameters? (yes/no): ", end='')
        response = input().strip().lower()
    else:
        # Auto-apply in non-verbose mode
        response = 'yes'
        logger.info("Auto-applying optimized parameters (verbose_logging=false)")
    
    if response in ['yes', 'y']:
        # Backup current config
        backup_file = optimizer.backup_config("before-optimization")
        if verbose:
            logger.info(f"Config backed up to: {backup_file}")
        
        # Update config
        optimizer.update_config(
            result['exponent'],
            result['max_score'],
            f"Optimized on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            verbose=verbose
        )
        
        if verbose:
            print("\n✓ Configuration updated successfully!")
            print(f"  • Dampening exponent: {result['exponent']}")
            print(f"  • Max theoretical score: {result['max_score']}")
            print(f"\nRe-run assessment to see the effect:")
            print(f"  python astra_report.py -c {config.config_path}")
        else:
            logger.info(f"✓ Dampening parameters optimized: exponent={result['exponent']}, max_score={result['max_score']}")
    else:
        print("\nOptimization cancelled. No changes made.")
    
    logger.info("="*80)


def main():
    """Main execution function."""
    # Parse arguments
    parser = ArgumentParser(
        description='ASTRA - Application Security Threat & Risk Assessment',
        epilog='Example: %(prog)s -c config.yaml'
    )
    parser.add_argument('-c', '--config', dest='config', required=True,
                       help='Path to configuration YAML file')
    parser.add_argument('--debug', dest='debug', action='store_true',
                       help='Enable debug logging')
    
    # HRP v2.0 dampening optimization
    parser.add_argument('--hrp-dampen', '-hd', dest='optimize_dampening', 
                       action='store_true',
                       help='Optimize HRP v2.0 dampening parameters for environment')
    
    args = parser.parse_args()
    
    # Load config first to check verbose_logging setting
    config = AstraConfig(args.config)
    
    # Configure logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    elif config.get('advanced.verbose_logging', False):
        logging.getLogger().setLevel(logging.INFO)
    else:
        # Keep default WARNING level for less verbose output
        pass
    
    logger.info("="*80)
    logger.info("ASTRA - Application Security Threat & Risk Assessment")
    logger.info("="*80)
    
    try:
        # Load configuration
        config = AstraConfig(args.config)
        
        # Execute assessment
        result_path = run_assessment(config)
        
        # If optimization requested, run it after assessment
        if args.optimize_dampening:
            run_dampening_optimization(config, result_path)
        
    except Exception as e:
        logger.error(f"Assessment failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
