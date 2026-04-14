#!/usr/bin/env python3
"""
ASTRA - Application Security Threat & Risk Assessment
Generates comprehensive risk assessment reports for Dynatrace-monitored applications.

Supports multiple phases:
- Phase 1: Current risk assessment with detailed scoring
- Phase 2: Temporal comparison and risk trend analysis (future)
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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
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
            logger.info(f"Configuration loaded from {self.config_path}")
            return config
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"Error parsing YAML configuration: {e}")
            sys.exit(1)
    
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
        
        data = {
            'security_problems': self._collect_security_problems(),
            'process_groups': self._collect_process_groups(),
            'hosts': self._collect_hosts()
        }
        
        logger.info(f"Data collection complete: "
                   f"{len(data['security_problems'])} security problems, "
                   f"{len(data['process_groups'])} process groups, "
                   f"{len(data['hosts'])} hosts")
        
        return data
    
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
    
    def _collect_security_problems(self) -> List[Dict[str, Any]]:
        """Collect all security problems with details (parallel processing)."""
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
        
        logger.info(f"Successfully enriched {len(enriched_problems)} security problems")
        return enriched_problems
    
    def _collect_process_groups(self) -> List[Dict[str, Any]]:
        """Collect process groups with properties and relationships."""
        logger.info("Collecting process groups...")
        
        # Get all hosts (which contain process relationships)
        hosts = self.api.getHosts()
        
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
    
    def _collect_hosts(self) -> List[Dict[str, Any]]:
        """Collect host information."""
        logger.info("Collecting hosts...")
        return self.api.getHosts()


class RiskCalculator:
    """Calculates risk scores using CWRS or REI methodology."""
    
    def __init__(self, config: AstraConfig):
        self.config = config
        self.risk_model = config.get('assessment.risk_model', 'CWRS').upper()
        self.weights = {
            'vulnerability': config.get('scoring.vulnerability_weight', 40),
            'exploitability': config.get('scoring.exploitability_weight', 25),
            'exposure': config.get('scoring.exposure_weight', 20),
            'criticality': config.get('scoring.criticality_weight', 15)
        }
        
    def calculate_overall_risk(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall application risk score based on selected model."""
        logger.info(f"Calculating overall risk score using {self.risk_model} model...")
        
        if self.risk_model == 'REI':
            return self._calculate_rei_risk(data)
        else:
            return self._calculate_cwrs_risk(data)
    
    def _calculate_cwrs_risk(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate CWRS (Composite Weighted Risk Score) - 0-100% scale."""
        vulnerabilities = data['security_problems']
        
        # Calculate component scores
        vuln_score = self._calculate_vulnerability_severity_score(vulnerabilities)
        exploit_score = self._calculate_exploitability_score(vulnerabilities)
        exposure_score = self._calculate_exposure_score(data)
        criticality_score = self._calculate_criticality_score(data)
        
        # Apply weights (already in percentage form)
        total_score = vuln_score + exploit_score + exposure_score + criticality_score
        
        risk_rating = self._get_risk_rating_cwrs(total_score)
        
        return {
            'score': round(total_score, 2),
            'rating': risk_rating,
            'model': 'CWRS',
            'components': {
                'vulnerability_severity': round(vuln_score, 2),
                'exploitability': round(exploit_score, 2),
                'exposure': round(exposure_score, 2),
                'criticality': round(criticality_score, 2)
            }
        }
    
    def calculate_entity_risk(self, entity: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate risk score for a specific entity based on selected model."""
        entity_id = entity.get('entityId')
        entity_name = entity.get('displayName', entity_id)
        
        # Filter vulnerabilities affecting this entity
        # Use relatedEntities to match process group instances
        entity_vulns = []
        for v in vulnerabilities:
            # Check relatedEntities for this PGI
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
        
        if self.risk_model == 'REI':
            return self._calculate_entity_risk_rei(entity, entity_vulns)
        else:
            return self._calculate_entity_risk_cwrs(entity, entity_vulns)
    
    def _calculate_entity_risk_cwrs(self, entity: Dict[str, Any], entity_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate CWRS risk for a specific entity."""
        entity_id = entity.get('entityId')
        entity_name = entity.get('displayName', entity_id)
        
        # Calculate scores
        vuln_score = self._calculate_vulnerability_severity_score(entity_vulns)
        exploit_score = self._calculate_exploitability_score(entity_vulns)
        exposure_score = self._calculate_entity_exposure_score(entity)
        criticality_score = self._calculate_entity_criticality_score(entity)
        
        total_score = vuln_score + exploit_score + exposure_score + criticality_score
        
        return {
            'entity_id': entity_id,
            'entity_name': entity_name,
            'entity_type': entity.get('type', 'UNKNOWN'),
            'risk_score': round(total_score, 2),
            'risk_rating': self._get_risk_rating_cwrs(total_score),
            'vulnerability_count': len(entity_vulns),
            'vulnerabilities': entity_vulns,
            'components': {
                'vulnerability_severity': round(vuln_score, 2),
                'exploitability': round(exploit_score, 2),
                'exposure': round(exposure_score, 2),
                'criticality': round(criticality_score, 2)
            }
        }
    
    def _calculate_entity_risk_rei(self, entity: Dict[str, Any], entity_vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate REI risk for a specific entity."""
        import math
        
        entity_id = entity.get('entityId')
        entity_name = entity.get('displayName', entity_id)
        
        # Create minimal data structure for REI calculation
        entity_data = {
            'security_problems': entity_vulns,
            'process_groups': [entity] if 'PROCESS_GROUP' in entity_id else [],
            'hosts': []
        }
        
        # Calculate REI for this entity
        rei_result = self._calculate_rei_risk(entity_data)
        
        return {
            'entity_id': entity_id,
            'entity_name': entity_name,
            'entity_type': entity.get('type', 'UNKNOWN'),
            'risk_score': rei_result['score'],
            'risk_rating': rei_result['rating'],
            'vulnerability_count': len(entity_vulns),
            'vulnerabilities': entity_vulns,
            'components': rei_result['components']
        }
    
    def _calculate_vulnerability_severity_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate vulnerability severity component (0-40 points)."""
        score = 0
        severity_points = {
            'CRITICAL': 10,
            'HIGH': 5,
            'MEDIUM': 2,
            'LOW': 0.5
        }
        
        for vuln in vulnerabilities:
            risk_assessment = vuln.get('riskAssessment', {})
            if isinstance(risk_assessment, dict):
                severity = risk_assessment.get('riskLevel', 'LOW')
                score += severity_points.get(severity, 0)
        
        return min(score, self.weights['vulnerability'])
    
    def _calculate_exploitability_score(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate exploitability component (0-25 points) without attack data."""
        score = 0
        
        for vuln in vulnerabilities:
            risk_assessment = vuln.get('riskAssessment', {})
            if not isinstance(risk_assessment, dict):
                continue
            
            # Check for public exposure
            exposure = risk_assessment.get('exposure', {})
            if isinstance(exposure, dict):
                if exposure.get('publicNetwork', False):
                    score += 10
                
                # Check for known exploits
                if exposure.get('publicExploit', False):
                    score += 5
            
            # Check for vulnerable function reachable
            if risk_assessment.get('vulnerableFunctionInUse', False):
                score += 5
        
        return min(score, self.weights['exploitability'])
    
    def _calculate_exposure_score(self, data: Dict[str, Any]) -> float:
        """Calculate overall attack surface exposure (0-20 points)."""
        score = 0
        vulnerabilities = data['security_problems']
        
        # Count vulnerable libraries (third-party components)
        vulnerable_components = set()
        for vuln in vulnerabilities:
            if 'vulnerableComponents' in vuln:
                for comp in vuln['vulnerableComponents']:
                    vulnerable_components.add(comp.get('id'))
        
        # +1 point per vulnerable library, cap at 10
        score += min(len(vulnerable_components), 10)
        
        # Check for database connections in process groups
        db_connections = 0
        for pg in data.get('process_groups', []):
            # Check if process has database-related properties
            props = pg.get('properties', {})
            if any('database' in str(v).lower() for v in props.values()):
                db_connections += 1
        
        # +2 points per DB connection, cap contribution at 10
        score += min(db_connections * 2, 10)
        
        return min(score, self.weights['exposure'])
    
    def _calculate_entity_exposure_score(self, entity: Dict[str, Any]) -> float:
        """Calculate exposure score for a specific entity."""
        score = 0
        props = entity.get('properties', {})
        
        # Check for network exposure indicators
        if props.get('networkListenerCount', 0) > 0:
            score += 5
        
        # Check technology stack
        if 'softwareTechnologies' in entity:
            score += min(len(entity['softwareTechnologies']), 5)
        
        return min(score, self.weights['exposure'])
    
    def _calculate_criticality_score(self, data: Dict[str, Any]) -> float:
        """Calculate overall system criticality (0-15 points)."""
        score = 0
        
        # Check management zones for production indicators
        prod_entities = 0
        for pg in data.get('process_groups', []):
            mzones = pg.get('managementZones', [])
            if any('prod' in mz.get('name', '').lower() for mz in mzones):
                prod_entities += 1
        
        if prod_entities > 0:
            score += 5
        
        # Process count indicator
        total_processes = len(data.get('process_groups', []))
        score += min(total_processes // 10, 5)
        
        # Host memory footprint
        high_memory_hosts = 0
        for host in data.get('hosts', []):
            memory = host.get('properties', {}).get('memoryTotal', 0)
            if memory > 16384:  # > 16GB
                high_memory_hosts += 1
        
        if high_memory_hosts > 0:
            score += 5
        
        return min(score, self.weights['criticality'])
    
    # ========== REI (Risk Exposure Index) Methods ==========
    
    def _calculate_rei_risk(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate REI (Risk Exposure Index) - logarithmic 1-10 scale."""
        import math
        from datetime import datetime
        
        vulnerabilities = data['security_problems']
        total_risk_points = 0
        
        # Component 1: Vulnerability Impact Score (via Davis Security Score)
        vuln_impact_points = self._calculate_rei_vuln_impact(vulnerabilities)
        total_risk_points += vuln_impact_points
        
        # Component 2: Blast Radius Multiplier
        blast_radius_multiplier = self._calculate_rei_blast_radius(vulnerabilities, data)
        total_risk_points *= blast_radius_multiplier
        
        # Component 3: Active Threat Intelligence (no attacks, only exploit available)
        threat_multiplier = self._calculate_rei_threat_intelligence(vulnerabilities)
        total_risk_points *= threat_multiplier
        
        # Component 4: Remediation Debt
        remediation_points = self._calculate_rei_remediation_debt(vulnerabilities)
        total_risk_points += remediation_points
        
        # Apply logarithmic formula: REI = log₁₀(Total_Risk_Points + 1) × 1.5
        rei_score = math.log10(total_risk_points + 1) * 1.5
        rei_score = min(max(rei_score, 1), 10)  # Cap between 1-10
        
        risk_rating = self._get_risk_rating_rei(rei_score)
        
        return {
            'score': round(rei_score, 2),
            'rating': risk_rating,
            'model': 'REI',
            'components': {
                'vulnerability_impact_points': round(vuln_impact_points, 2),
                'blast_radius_multiplier': round(blast_radius_multiplier, 2),
                'threat_multiplier': round(threat_multiplier, 2),
                'remediation_debt_points': round(remediation_points, 2),
                'total_risk_points': round(total_risk_points, 2)
            }
        }
    
    def _calculate_rei_vuln_impact(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate vulnerability impact using Davis Security Score."""
        points = 0
        
        for vuln in vulnerabilities:
            risk_assessment = vuln.get('riskAssessment', {})
            if not isinstance(risk_assessment, dict):
                continue
            
            # Get Davis Security Score (riskScore) - preferred over CVSS baseRiskScore
            davis_score = risk_assessment.get('riskScore', 0)
            
            # If no Davis score, fall back to baseRiskScore (CVSS), then severity level
            if davis_score == 0:
                davis_score = risk_assessment.get('baseRiskScore', 0)
            
            if davis_score == 0:
                severity = risk_assessment.get('riskLevel', 'LOW')
                davis_map = {'CRITICAL': 9.5, 'HIGH': 7.5, 'MEDIUM': 5.0, 'LOW': 2.0}
                davis_score = davis_map.get(severity, 0)
            
            # Apply Davis Security Score-based points
            if davis_score >= 9.0:
                points += 1000
            elif davis_score >= 7.0:
                points += 500
            elif davis_score >= 4.0:
                points += 100
            elif davis_score > 0:
                points += 10
        
        return points
    
    def _calculate_rei_blast_radius(self, vulnerabilities: List[Dict[str, Any]], 
                                     data: Dict[str, Any]) -> float:
        """Calculate blast radius multiplier based on affected entities."""
        multiplier = 1.0
        
        # Count affected entities
        affected_pgs = set()
        affected_hosts = set()
        
        for vuln in vulnerabilities:
            remediation_items = vuln.get('remediationItems', [])
            for item in remediation_items:
                entity_id = item.get('id', '')
                if 'PROCESS_GROUP' in entity_id:
                    affected_pgs.add(entity_id)
                elif 'HOST' in entity_id:
                    affected_hosts.add(entity_id)
        
        # Apply multipliers
        multiplier *= (1.2 ** len(affected_pgs))  # 1.2 per PG
        multiplier *= (1.5 ** len(affected_hosts))  # 1.5 per host
        
        # Cap multiplier to prevent extreme values
        return min(multiplier, 100.0)
    
    def _calculate_rei_threat_intelligence(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate threat intelligence multiplier (no CISA KEV)."""
        multiplier = 1.0
        exploit_available_count = 0
        
        for vuln in vulnerabilities:
            risk_assessment = vuln.get('riskAssessment', {})
            if not isinstance(risk_assessment, dict):
                continue
            
            exposure = risk_assessment.get('exposure', {})
            if isinstance(exposure, dict):
                # Check for public exploit availability
                if exposure.get('publicExploit', False):
                    exploit_available_count += 1
        
        # Apply ×2 multiplier if exploits are available
        if exploit_available_count > 0:
            multiplier = 2.0
        
        return multiplier
    
    def _calculate_rei_remediation_debt(self, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate remediation debt points based on age and unremediated items."""
        from datetime import datetime
        import time
        
        points = 0
        unremediated_count = 0
        
        for vuln in vulnerabilities:
            # Check if unremediated
            status = vuln.get('status', 'OPEN')
            if status == 'OPEN':
                unremediated_count += 1
            
            # Calculate age
            first_seen = vuln.get('firstSeenTimestamp', 0)
            if first_seen > 0:
                # Convert milliseconds to days
                age_days = (time.time() * 1000 - first_seen) / (1000 * 60 * 60 * 24)
                
                risk_assessment = vuln.get('riskAssessment', {})
                if isinstance(risk_assessment, dict):
                    severity = risk_assessment.get('riskLevel', 'LOW')
                    
                    # Add points per day based on severity
                    if severity == 'CRITICAL':
                        points += age_days * 10
                    elif severity == 'HIGH':
                        points += age_days * 5
        
        # Add points for unremediated items
        points += unremediated_count * 50
        
        return points
    
    def _calculate_entity_criticality_score(self, entity: Dict[str, Any]) -> float:
        """Calculate criticality score for a specific entity."""
        score = 0
        
        # Management zone check
        mzones = entity.get('managementZones', [])
        if any('prod' in mz.get('name', '').lower() for mz in mzones):
            score += 5
        
        # Process instance count (if available)
        if 'instanceCount' in entity.get('properties', {}):
            count = entity['properties']['instanceCount']
            score += min(count // 10, 5)
        
        return min(score, self.weights['criticality'])
    
    def _get_risk_rating_cwrs(self, score: float) -> str:
        """Convert CWRS score (0-100) to rating."""
        if score >= 70:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 30:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_risk_rating_rei(self, rei_score: float) -> str:
        """Convert REI score (1-10) to rating."""
        if rei_score >= 9:
            return 'CRITICAL'
        elif rei_score >= 7:
            return 'HIGH'
        elif rei_score >= 4:
            return 'MEDIUM'
        else:
            return 'LOW'


class JsonExporter:
    """Exports assessment results to JSON format."""
    
    def __init__(self, config: AstraConfig):
        self.config = config
        
    def export(self, data: Dict[str, Any], overall_risk: Dict[str, Any], 
               entity_risks: List[Dict[str, Any]]) -> str:
        """Export complete assessment to JSON file."""
        timestamp = datetime.now()
        report_id = f"astra_{timestamp.strftime('%Y%m%d_%H%M%S')}"
        
        report = {
            'metadata': {
                'report_id': report_id,
                'generated_at': timestamp.isoformat(),
                'timeframe': self.config.get('assessment.timeframe'),
                'risk_model': self.config.get('assessment.risk_model', 'CWRS'),
                'astra_version': '1.0.0',
                'host_count': len(data.get('hosts', []))
            },
            'config': {
                'filters': self.config.get('filters', {}),
                'scoring': self.config.get('scoring', {})
            },
            'overall_risk': overall_risk,
            'entities': entity_risks,
            'summary': self._generate_summary(data, entity_risks)
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
    """Generates PDF reports from assessment data."""
    
    def __init__(self, config: AstraConfig):
        self.config = config
        
    def generate(self, json_file: str) -> str:
        """Generate PDF report from JSON data."""
        if not REPORTLAB_AVAILABLE:
            logger.warning("reportlab library not installed. Install with: pip install reportlab")
            logger.info("Skipping PDF generation, JSON report is available")
            return ""
            
        # Load JSON data
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Create output directory
        output_path = Path(self.config.get('output.pdf_path', './reports'))
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate PDF filename
        report_id = data['metadata']['report_id']
        pdf_file = output_path / f"{report_id}.pdf"
        
        # Generate PDF using reportlab
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        
        # Make classes available to helper methods
        self.Paragraph = Paragraph
        self.Spacer = Spacer
        self.Table = Table
        self.TableStyle = TableStyle
        self.PageBreak = PageBreak
        self.inch = inch
        
        doc = SimpleDocTemplate(str(pdf_file), pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f77b4'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        story.append(Paragraph("ASTRA Risk Assessment Report", title_style))
        story.append(Spacer(1, 0.3*inch))
        
        # Metadata
        story.append(Paragraph(f"<b>Report ID:</b> {data['metadata']['report_id']}", styles['Normal']))
        story.append(Paragraph(f"<b>Generated:</b> {data['metadata']['generated_at']}", styles['Normal']))
        story.append(Paragraph(f"<b>Timeframe:</b> {data['metadata']['timeframe']}", styles['Normal']))
        story.append(Paragraph(f"<b>Risk Model:</b> {data['metadata'].get('risk_model', 'CWRS')}", styles['Normal']))
        story.append(Spacer(1, 0.5*inch))
        
        # Overall Risk Score
        overall_risk = data['overall_risk']
        risk_model = overall_risk.get('model', 'CWRS')
        risk_color = self._get_risk_color(overall_risk['rating'])
        
        story.append(Paragraph("Overall Risk Score", styles['Heading2']))
        
        # Different display based on model
        if risk_model == 'REI':
            risk_table = Table([
                ['Risk Score', 'Risk Rating', 'Scale'],
                [f"{overall_risk['score']}/10", overall_risk['rating'], 'REI (1-10)']
            ], colWidths=[2*inch, 2*inch, 2*inch])
        else:
            risk_table = Table([
                ['Risk Score', 'Risk Rating', 'Scale'],
                [f"{overall_risk['score']}/100", overall_risk['rating'], 'CWRS (0-100%)']
            ], colWidths=[2*inch, 2*inch, 2*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('BACKGROUND', (1, 1), (1, 1), risk_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('FONTSIZE', (0, 1), (-1, 1), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Risk Component Breakdown
        story.append(Paragraph("Risk Component Breakdown", styles['Heading2']))
        components = overall_risk['components']
        
        # Different component display based on model
        if risk_model == 'REI':
            comp_data = [
                ['Component', 'Value'],
                ['Vulnerability Impact Points', f"{components.get('vulnerability_impact_points', 0):.0f}"],
                ['Blast Radius Multiplier', f"{components.get('blast_radius_multiplier', 1):.2f}x"],
                ['Threat Intelligence Multiplier', f"{components.get('threat_multiplier', 1):.2f}x"],
                ['Remediation Debt Points', f"{components.get('remediation_debt_points', 0):.0f}"],
                ['Total Risk Points', f"{components.get('total_risk_points', 0):.0f}"]
            ]
            comp_table = Table(comp_data, colWidths=[3*inch, 2*inch])
        else:
            comp_data = [
                ['Component', 'Score', 'Weight'],
                ['Vulnerability Severity', f"{components['vulnerability_severity']}", '40%'],
                ['Exploitability', f"{components['exploitability']}", '25%'],
                ['Exposure', f"{components['exposure']}", '20%'],
                ['Criticality', f"{components['criticality']}", '15%']
            ]
            comp_table = Table(comp_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
        comp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(comp_table)
        story.append(Spacer(1, 0.5*inch))
        
        # Summary Statistics
        summary = data['summary']
        story.append(Paragraph("Summary", styles['Heading2']))
        story.append(Paragraph(f"<b>Total Entities Analyzed:</b> {summary['total_entities']}", styles['Normal']))
        story.append(Paragraph(f"<b>Total Vulnerabilities:</b> {summary['total_vulnerabilities']}", styles['Normal']))
        story.append(Paragraph(f"<b>High-Risk Entities:</b> {summary['high_risk_entities']}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Vulnerabilities by Severity
        by_sev = summary['by_severity']
        sev_data = [
            ['Severity', 'Count'],
            ['Critical', by_sev['CRITICAL']],
            ['High', by_sev['HIGH']],
            ['Medium', by_sev['MEDIUM']],
            ['Low', by_sev['LOW']]
        ]
        sev_table = Table(sev_data, colWidths=[3*inch, 2*inch])
        sev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(sev_table)
        story.append(PageBreak())
        
        # Entity Risk Details
        story.append(Paragraph("Entity Risk Details", styles['Heading2']))
        story.append(Spacer(1, 0.2*inch))
        
        # Sort entities by risk score
        entities = sorted(data['entities'], key=lambda x: x['risk_score'], reverse=True)
        
        # Get risk model to determine scale
        risk_model = data['overall_risk'].get('model', 'CWRS')
        scale_max = "10" if risk_model == 'REI' else "100"
        
        for entity in entities[:20]:  # Limit to top 20 for MVP
            story.append(Paragraph(f"<b>{entity['entity_name']}</b>", styles['Heading3']))
            story.append(Paragraph(f"Type: {entity['entity_type']}", styles['Normal']))
            story.append(Paragraph(
                f"Risk Score: <b>{entity['risk_score']}/{scale_max}</b> ({entity['risk_rating']})",
                styles['Normal']
            ))
            story.append(Paragraph(f"Vulnerabilities: {entity['vulnerability_count']}", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        # Add detailed component analysis page
        story.append(PageBreak())
        self._add_component_analysis_page(story, data, styles)
        
        # Add scoring methodology page
        story.append(PageBreak())
        self._add_methodology_page(story, data, styles)
        
        # Build PDF
        doc.build(story)
        logger.info(f"PDF report saved to {pdf_file}")
        return str(pdf_file)
    
    def _add_component_analysis_page(self, story: List, data: Dict[str, Any], styles):
        """Add detailed component analysis page."""
        overall_risk = data['overall_risk']
        risk_model = overall_risk.get('model', 'CWRS')
        components = overall_risk['components']
        summary = data['summary']
        
        story.append(self.Paragraph("Detailed Component Analysis", styles['Heading1']))
        story.append(self.Spacer(1, 0.3*self.inch))
        
        story.append(self.Paragraph(
            "This page provides a detailed breakdown of how each component contributed to the overall risk score.",
            styles['Normal']
        ))
        story.append(self.Spacer(1, 0.3*self.inch))
        
        if risk_model == 'REI':
            # REI Model Analysis
            story.append(self.Paragraph("1. Vulnerability Impact Points", styles['Heading2']))
            story.append(self.Paragraph(
                f"<b>Value:</b> {components.get('vulnerability_impact_points', 0):,.0f} points",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            # Calculate vulnerability impact breakdown
            by_sev = summary['by_severity']
            critical_points = by_sev['CRITICAL'] * 1000
            high_points = by_sev['HIGH'] * 500
            medium_points = by_sev['MEDIUM'] * 100
            low_points = by_sev['LOW'] * 10
            
            vuln_breakdown = [
                ['Severity', 'Count', 'Points Each', 'Total Points'],
                ['Critical (9.0-10.0 Davis Score)', str(by_sev['CRITICAL']), '1,000', f"{critical_points:,}"],
                ['High (7.0-8.9 Davis Score)', str(by_sev['HIGH']), '500', f"{high_points:,}"],
                ['Medium (4.0-6.9 Davis Score)', str(by_sev['MEDIUM']), '100', f"{medium_points:,}"],
                ['Low (0.1-3.9 Davis Score)', str(by_sev['LOW']), '10', f"{low_points:,}"]
            ]
            vuln_table = self.Table(vuln_breakdown, colWidths=[2*self.inch, 1*self.inch, 1.2*self.inch, 1.3*self.inch])
            vuln_table.setStyle(self.TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)
            story.append(self.Spacer(1, 0.2*self.inch))
            
            story.append(self.Paragraph(
                "This component measures the inherent severity of vulnerabilities using Davis Security Score. "
                "Critical vulnerabilities receive exponentially higher points to emphasize their urgency.",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.3*self.inch))
            
            # Blast Radius Multiplier
            story.append(self.Paragraph("2. Blast Radius Multiplier", styles['Heading2']))
            story.append(self.Paragraph(
                f"<b>Value:</b> {components.get('blast_radius_multiplier', 1):.2f}x",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            story.append(self.Paragraph(
                f"<b>Process Groups Affected:</b> {summary.get('total_entities', 0)} "
                f"(multiplier: 1.2 per PG)",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                f"<b>Hosts Affected:</b> {data['metadata'].get('host_count', 0)} "
                f"(multiplier: 1.5 per host)",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            story.append(self.Paragraph(
                "This multiplier scales risk exponentially based on how many entities are affected. "
                "A vulnerability affecting many process groups or hosts has a much larger potential impact.",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.3*self.inch))
            
            # Threat Intelligence
            story.append(self.Paragraph("3. Threat Intelligence Multiplier", styles['Heading2']))
            story.append(self.Paragraph(
                f"<b>Value:</b> {components.get('threat_multiplier', 1):.2f}x",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            exploitable_count = sum(1 for sp in data.get('security_problems', [])
                                  if sp.get('riskAssessment', {}).get('exposure', '') == 'PUBLIC_NETWORK')
            
            story.append(self.Paragraph(
                f"<b>Publicly Exploitable Vulnerabilities:</b> {exploitable_count}",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            story.append(self.Paragraph(
                "This multiplier increases (×2) when vulnerabilities have known public exploits. "
                "It reflects the real-world likelihood that attackers can leverage these weaknesses.",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.3*self.inch))
            
            # Remediation Debt
            story.append(self.Paragraph("4. Remediation Debt Points", styles['Heading2']))
            story.append(self.Paragraph(
                f"<b>Value:</b> {components.get('remediation_debt_points', 0):,.0f} points",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            story.append(self.Paragraph(
                "This component penalizes old, unremediated vulnerabilities. Points accumulate based on:",
                styles['Normal']
            ))
            story.append(self.Paragraph("• Critical vulnerabilities: 10 points per day", styles['Normal']))
            story.append(self.Paragraph("• High vulnerabilities: 5 points per day", styles['Normal']))
            story.append(self.Paragraph("• Each unremediated item: +50 base points", styles['Normal']))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            story.append(self.Paragraph(
                "Long-standing vulnerabilities significantly increase risk as attackers have more time "
                "to discover and exploit them.",
                styles['Normal']
            ))
            
        else:
            # CWRS Model Analysis
            story.append(self.Paragraph("1. Vulnerability Severity Component", styles['Heading2']))
            story.append(self.Paragraph(
                f"<b>Score:</b> {components['vulnerability_severity']}/40 points (40% weight)",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            by_sev = summary['by_severity']
            vuln_breakdown = [
                ['Severity', 'Count', 'Points Each', 'Contribution'],
                ['Critical', str(by_sev['CRITICAL']), '10', f"{min(by_sev['CRITICAL'] * 10, 40)}"],
                ['High', str(by_sev['HIGH']), '5', f"{by_sev['HIGH'] * 5}"],
                ['Medium', str(by_sev['MEDIUM']), '2', f"{by_sev['MEDIUM'] * 2}"],
                ['Low', str(by_sev['LOW']), '0.5', f"{by_sev['LOW'] * 0.5}"]
            ]
            vuln_table = self.Table(vuln_breakdown, colWidths=[1.5*self.inch, 1*self.inch, 1.2*self.inch, 1.3*self.inch])
            vuln_table.setStyle(self.TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)
            story.append(self.Spacer(1, 0.2*self.inch))
            
            story.append(self.Paragraph(
                "This component measures the raw severity of identified vulnerabilities based on CVE classifications. "
                "Capped at 40 points maximum.",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.3*self.inch))
            
            # Exploitability
            story.append(self.Paragraph("2. Exploitability Component", styles['Heading2']))
            story.append(self.Paragraph(
                f"<b>Score:</b> {components['exploitability']}/25 points (25% weight)",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            exploitable_count = sum(1 for sp in data.get('security_problems', [])
                                  if sp.get('riskAssessment', {}).get('exposure', '') == 'PUBLIC_NETWORK')
            
            story.append(self.Paragraph(
                f"<b>Publicly Exposed Vulnerabilities:</b> {exploitable_count}",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            story.append(self.Paragraph(
                "This component assesses how easily vulnerabilities can be exploited, considering public exposure, "
                "known exploits, and attack surface. Capped at 25 points.",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.3*self.inch))
            
            # Exposure
            story.append(self.Paragraph("3. Exposure Component", styles['Heading2']))
            story.append(self.Paragraph(
                f"<b>Score:</b> {components['exposure']}/20 points (20% weight)",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            story.append(self.Paragraph(
                f"<b>Affected Process Groups:</b> {summary.get('total_entities', 0)}",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                f"<b>Total Vulnerabilities:</b> {summary['total_vulnerabilities']}",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            story.append(self.Paragraph(
                "This component measures attack surface and blast radius - how many systems and entry points "
                "are vulnerable. Capped at 20 points.",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.3*self.inch))
            
            # Criticality
            story.append(self.Paragraph("4. System Criticality Component", styles['Heading2']))
            story.append(self.Paragraph(
                f"<b>Score:</b> {components['criticality']}/15 points (15% weight)",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            story.append(self.Paragraph(
                "This component evaluates the business criticality of affected systems based on management zones, "
                "resource usage, and production classification. Capped at 15 points.",
                styles['Normal']
            ))
    
    def _add_methodology_page(self, story: List, data: Dict[str, Any], styles):
        """Add scoring methodology explanation page."""
        overall_risk = data['overall_risk']
        risk_model = overall_risk.get('model', 'CWRS')
        
        story.append(self.Paragraph("Understanding the Risk Score", styles['Heading1']))
        story.append(self.Spacer(1, 0.3*self.inch))
        
        if risk_model == 'REI':
            # REI Methodology
            story.append(self.Paragraph("Risk Exposure Index (REI) Methodology", styles['Heading2']))
            story.append(self.Spacer(1, 0.2*self.inch))
            
            story.append(self.Paragraph("<b>Scale: 1-10 (Logarithmic)</b>", styles['Normal']))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            story.append(self.Paragraph(
                "The REI uses a logarithmic scale similar to the Richter scale for earthquakes. "
                "Each increase in the score represents an exponentially higher level of risk.",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.2*self.inch))
            
            # Formula
            story.append(self.Paragraph("<b>Calculation Formula:</b>", styles['Heading3']))
            story.append(self.Paragraph(
                "REI = log₁₀(Total Risk Points + 1) × 1.5",
                styles['Code']
            ))
            story.append(self.Spacer(1, 0.2*self.inch))
            
            # Risk Levels
            story.append(self.Paragraph("<b>Risk Level Interpretation:</b>", styles['Heading3']))
            
            risk_levels = [
                ['Score Range', 'Risk Level', 'Meaning'],
                ['1.0 - 3.0', 'LOW', 'Minimal vulnerabilities, well-maintained systems'],
                ['3.1 - 5.0', 'MODERATE', 'Some vulnerabilities, manageable exposure'],
                ['5.1 - 7.0', 'ELEVATED', 'Notable vulnerabilities requiring attention'],
                ['7.1 - 8.5', 'HIGH', 'Significant vulnerabilities with exploitation potential'],
                ['8.6 - 10.0', 'CRITICAL', 'Severe vulnerabilities, large blast radius, immediate action required']
            ]
            
            risk_table = self.Table(risk_levels, colWidths=[1.3*self.inch, 1.2*self.inch, 3*self.inch])
            risk_table.setStyle(self.TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (1, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            story.append(risk_table)
            story.append(self.Spacer(1, 0.3*self.inch))
            
            # How to use
            story.append(self.Paragraph("<b>How to Use This Score:</b>", styles['Heading3']))
            story.append(self.Paragraph(
                "• <b>Trend Monitoring:</b> Track REI changes over time. A change of ±1 point is significant.",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                "• <b>Prioritization:</b> Higher REI scores indicate exponentially higher risk and should be addressed first.",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                "• <b>Resource Allocation:</b> Use REI to justify security investments and remediation efforts.",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.2*self.inch))
            
            # Key Factors
            story.append(self.Paragraph("<b>Key Risk Amplifiers:</b>", styles['Heading3']))
            story.append(self.Paragraph(
                "• <b>Critical Davis Security Scores:</b> Vulnerabilities with Davis Score 9.0+ contribute 1,000 points each",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                "• <b>Blast Radius:</b> More affected systems exponentially increase risk",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                "• <b>Public Exploits:</b> Known exploits double the threat multiplier",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                "• <b>Age:</b> Unremediated vulnerabilities accumulate debt points daily",
                styles['Normal']
            ))
            
        else:
            # CWRS Methodology
            story.append(self.Paragraph("Composite Weighted Risk Score (CWRS) Methodology", styles['Heading2']))
            story.append(self.Spacer(1, 0.2*self.inch))
            
            story.append(self.Paragraph("<b>Scale: 0-100%</b>", styles['Normal']))
            story.append(self.Spacer(1, 0.1*self.inch))
            
            story.append(self.Paragraph(
                "The CWRS provides a comprehensive risk assessment by combining multiple weighted components "
                "into a single percentage score.",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.2*self.inch))
            
            # Formula
            story.append(self.Paragraph("<b>Calculation Formula:</b>", styles['Heading3']))
            story.append(self.Paragraph(
                "Risk% = (Vulnerability × 40%) + (Exploitability × 25%) + (Exposure × 20%) + (Criticality × 15%)",
                styles['Code']
            ))
            story.append(self.Spacer(1, 0.2*self.inch))
            
            # Risk Levels
            story.append(self.Paragraph("<b>Risk Level Interpretation:</b>", styles['Heading3']))
            
            risk_levels = [
                ['Score Range', 'Risk Level', 'Meaning'],
                ['0 - 25%', 'LOW', 'Minimal security concerns, routine monitoring sufficient'],
                ['26 - 50%', 'MODERATE', 'Some concerns, regular review recommended'],
                ['51 - 70%', 'HIGH', 'Significant risks, immediate remediation planning required'],
                ['71 - 100%', 'CRITICAL', 'Severe risks, urgent action and executive awareness needed']
            ]
            
            risk_table = self.Table(risk_levels, colWidths=[1.3*self.inch, 1.2*self.inch, 3*self.inch])
            risk_table.setStyle(self.TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (1, -1), 'CENTER'),
                ('ALIGN', (2, 0), (2, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
            ]))
            story.append(risk_table)
            story.append(self.Spacer(1, 0.3*self.inch))
            
            # How to use
            story.append(self.Paragraph("<b>How to Use This Score:</b>", styles['Heading3']))
            story.append(self.Paragraph(
                "• <b>Threshold Management:</b> Set organizational thresholds (e.g., remediate when >50%)",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                "• <b>Trend Analysis:</b> Compare scores monthly to track improvement or degradation",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                "• <b>Component Focus:</b> Target the highest-weighted components for maximum impact",
                styles['Normal']
            ))
            story.append(self.Spacer(1, 0.2*self.inch))
            
            # Component Weights
            story.append(self.Paragraph("<b>Component Weight Rationale:</b>", styles['Heading3']))
            story.append(self.Paragraph(
                "• <b>Vulnerability (40%):</b> Direct security impact - the foundation of risk",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                "• <b>Exploitability (25%):</b> Real-world attack likelihood",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                "• <b>Exposure (20%):</b> Attack surface and blast radius",
                styles['Normal']
            ))
            story.append(self.Paragraph(
                "• <b>Criticality (15%):</b> Business impact context",
                styles['Normal']
            ))
        
        story.append(self.Spacer(1, 0.3*self.inch))
        story.append(self.Paragraph("<b>Recommended Actions:</b>", styles['Heading3']))
        
        current_score = overall_risk['score']
        rating = overall_risk['rating']
        
        if rating == 'CRITICAL':
            story.append(self.Paragraph(
                "🔴 <b>URGENT:</b> Immediate executive notification required. Implement emergency remediation plan. "
                "Consider shutting down affected systems until critical vulnerabilities are patched.",
                styles['Normal']
            ))
        elif rating == 'HIGH':
            story.append(self.Paragraph(
                "🟠 <b>HIGH PRIORITY:</b> Schedule remediation within 7 days. Increase monitoring. "
                "Prioritize critical and high severity vulnerabilities first.",
                styles['Normal']
            ))
        elif rating in ['MODERATE', 'MEDIUM']:
            story.append(self.Paragraph(
                "🟡 <b>MODERATE:</b> Plan remediation within 30 days. Review and update security policies. "
                "Focus on high-severity items and exposed systems.",
                styles['Normal']
            ))
        else:
            story.append(self.Paragraph(
                "🟢 <b>LOW:</b> Maintain current security posture. Continue routine monitoring and patching. "
                "Address remaining items during regular maintenance windows.",
                styles['Normal']
            ))
    
    def _get_risk_color(self, rating: str):
        """Get color based on risk rating."""
        color_map = {
            'CRITICAL': colors.red,
            'HIGH': colors.orange,
            'MEDIUM': colors.yellow,
            'LOW': colors.lightgreen
        }
        return color_map.get(rating, colors.grey)


def run_phase1(config: AstraConfig) -> None:
    """Execute Phase 1: Current risk assessment without temporal comparison.
    
    Args:
        config: Loaded ASTRA configuration
    """
    logger.info("Running Phase 1: Current Risk Assessment")
    
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
    
    # Log overall risk with appropriate scale
    risk_model = config.get('assessment.risk_model', 'CWRS')
    scale_max = "10" if risk_model == 'REI' else "100"
    logger.info(f"Overall Risk Score: {overall_risk['score']}/{scale_max} ({overall_risk['rating']})")
    
    # Calculate entity-level risks
    entity_risks = []
    for pg in data['process_groups']:
        entity_risk = calculator.calculate_entity_risk(pg, data['security_problems'])
        if entity_risk['vulnerability_count'] > 0:
            entity_risks.append(entity_risk)
    
    logger.info(f"Analyzed {len(entity_risks)} entities with vulnerabilities")
    
    # Export JSON
    json_exporter = JsonExporter(config)
    json_file = json_exporter.export(data, overall_risk, entity_risks)
    
    # Generate PDF
    pdf_generator = PdfGenerator(config)
    pdf_file = pdf_generator.generate(json_file)
    
    logger.info("="*80)
    logger.info("Phase 1 Assessment Complete!")
    logger.info(f"JSON Report: {json_file}")
    if pdf_file:
        logger.info(f"PDF Report: {pdf_file}")
    logger.info("="*80)


def run_phase2(config: AstraConfig, baseline_report: Optional[str] = None) -> None:
    """Execute Phase 2: Temporal comparison and trend analysis.
    
    Args:
        config: Loaded ASTRA configuration
        baseline_report: Path to baseline JSON report for comparison (optional)
    """
    logger.info("Running Phase 2: Temporal Comparison & Trend Analysis")
    logger.warning("Phase 2 is not yet implemented. This is a placeholder for future functionality.")
    logger.info("Phase 2 will include:")
    logger.info("  - Comparison with previous JSON snapshots")
    logger.info("  - Risk trend analysis (improvement/degradation)")
    logger.info("  - Velocity calculations (risk change over time)")
    logger.info("  - Identification of new/resolved vulnerabilities")
    logger.info("  - Trend visualizations in PDF reports")
    # TODO: Implement Phase 2 logic
    raise NotImplementedError("Phase 2 functionality will be implemented in a future version")


def main():
    """Main execution function with phase selection."""
    # Parse arguments
    parser = ArgumentParser(
        description='ASTRA - Application Security Threat & Risk Assessment',
        epilog='Example: %(prog)s -c config.yaml --phase-1'
    )
    parser.add_argument('-c', '--config', dest='config', required=True,
                       help='Path to configuration YAML file')
    parser.add_argument('--debug', dest='debug', action='store_true',
                       help='Enable debug logging')
    
    # Phase selection (mutually exclusive)
    phase_group = parser.add_mutually_exclusive_group()
    phase_group.add_argument('-1', '--phase-1', dest='phase1', action='store_true',
                           help='Run Phase 1: Current risk assessment (default)')
    phase_group.add_argument('-2', '--phase-2', dest='phase2', action='store_true',
                           help='Run Phase 2: Temporal comparison and trend analysis')
    
    # Phase 2 specific arguments
    parser.add_argument('--baseline', dest='baseline', type=str,
                       help='Path to baseline JSON report for Phase 2 comparison')
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Default to Phase 1 if no phase specified
    if not args.phase1 and not args.phase2:
        args.phase1 = True
    
    logger.info("="*80)
    logger.info("ASTRA - Application Security Threat & Risk Assessment")
    logger.info("="*80)
    
    try:
        # Load configuration
        config = AstraConfig(args.config)
        
        # Execute selected phase
        if args.phase1:
            run_phase1(config)
        elif args.phase2:
            run_phase2(config, baseline_report=args.baseline)
        
    except NotImplementedError as e:
        logger.error(f"{e}")
        sys.exit(2)
    except Exception as e:
        logger.error(f"Assessment failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
