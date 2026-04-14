#!/usr/bin/env python
"""
Production Promotion GO/NO-GO Decision Script

This script evaluates security vulnerabilities in a Certification Environment
to determine if an application is ready for production promotion.

Supports two modes:
- Evaluate Mode: Standalone assessment of certification environment
- Compare Mode: Comparative assessment between certification and production

Author: Dynatrace AppSec Team
Version: 1.0.0
"""

import sys
from pathlib import Path

# Add parent directory to sys.path to import shared modules
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
import json
import csv
import logging
import logging.config
from argparse import ArgumentParser
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from dynatrace_api import DynatraceApi
import io
import builtins

# Store original print
_original_print = builtins.print

# Quiet wrapper for DynatraceApi that suppresses progress dots
class QuietDynatraceApi(DynatraceApi):
    """Wrapper around DynatraceApi that suppresses output when quiet=True"""
    def __init__(self, tenant, apiToken, verifySSL=True, quiet=False):
        super().__init__(tenant, apiToken, verifySSL)
        self._quiet = quiet
        if quiet:
            # Monkey-patch print globally to filter out dots
            builtins.print = self._quiet_print
    
    def _quiet_print(self, *args, **kwargs):
        """Filtered print that suppresses dots"""
        # Only suppress single dot prints (the progress indicator)
        if len(args) == 1 and args[0] == '.' and kwargs.get('end', '\n') == "" and kwargs.get('flush', False):
            return  # Suppress the dot
        _original_print(*args, **kwargs)  # Allow all other prints

# ANSI Color codes for terminal output
class Colors:
    RED = '\033[91m'
    ORANGE = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

class VulnerabilityAssessment:
    """Handles vulnerability assessment logic for GO/NO-GO decisions"""
    
    def __init__(self, config: Dict, verbose: bool = False, quiet: bool = False):
        self.config = config
        self.verbose = verbose
        self.quiet = quiet  # Suppress all output for machine-readable mode
        self.mode = config.get('mode', 'evaluate').lower()
        self.logger = logging.getLogger(__name__)
        
        # Parallel execution settings
        self.max_workers = config.get('max_workers', 10)  # Default to 10 concurrent requests
        
        # Assessment rules configuration
        self.assessment_rules = config.get('assessment_rules', {})
        self.excluded_cves = set(self.assessment_rules.get('excluded_cves', []))
        self.severity_exclusions = self.assessment_rules.get('severity_exclusions', {})
        self.thresholds = self.assessment_rules.get('thresholds', {})
        
        self.logger.info(f"Excluded CVEs: {self.excluded_cves}")
        self.logger.info(f"Severity exclusions: {self.severity_exclusions}")
        
        # Initialize Dynatrace API clients
        self._init_api_clients()
        
    def _init_api_clients(self):
        """Initialize Dynatrace API client(s) based on mode"""
        if self.mode == 'evaluate':
            cert_config = self.config['certification_environment']
            self.cert_api = QuietDynatraceApi(
                cert_config['url'],
                cert_config['token'],
                cert_config.get('verify_ssl', True),
                quiet=self.quiet
            )
            self.logger.info(f"Initialized API for certification environment: {cert_config['url']}")
        
        elif self.mode == 'compare':
            cert_config = self.config['certification_environment']
            prod_config = self.config['production_environment']
            
            self.cert_api = QuietDynatraceApi(
                cert_config['url'],
                cert_config['token'],
                cert_config.get('verify_ssl', True),
                quiet=self.quiet
            )
            self.prod_api = QuietDynatraceApi(
                prod_config['url'],
                prod_config['token'],
                prod_config.get('verify_ssl', True),
                quiet=self.quiet
            )
            self.logger.info(f"Initialized API for certification: {cert_config['url']}")
            self.logger.info(f"Initialized API for production: {prod_config['url']}")
    
    def run_assessment(self) -> Dict:
        """Main assessment execution"""
        self.logger.info(f"Starting assessment in {self.mode.upper()} mode")
        if not self.quiet:
            print(f"\n{Colors.BOLD}=== Production Promotion Assessment ==={Colors.END}")
            print(f"Mode: {Colors.BLUE}{self.mode.upper()}{Colors.END}")
            print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Get certification environment vulnerabilities
        cert_vulns = self._fetch_vulnerabilities('certification_environment', self.cert_api)
        
        results = {
            'mode': self.mode,
            'timestamp': datetime.now().isoformat(),
            'certification': {
                'vulnerabilities': cert_vulns,
                'total_count': len(cert_vulns)
            }
        }
        
        if self.mode == 'compare':
            # Get production environment vulnerabilities
            prod_vulns = self._fetch_vulnerabilities('production_environment', self.prod_api)
            results['production'] = {
                'vulnerabilities': prod_vulns,
                'total_count': len(prod_vulns)
            }
            
            # Perform comparative analysis
            comparison = self._compare_vulnerabilities(cert_vulns, prod_vulns)
            results['comparison'] = comparison
        
        # Make GO/NO-GO decision
        decision = self._make_decision(results)
        results['decision'] = decision
        
        return results
    
    def _fetch_vulnerabilities(self, env_name: str, api: DynatraceApi) -> List[Dict]:
        """Fetch vulnerabilities from Dynatrace environment"""
        self.logger.info(f"Fetching vulnerabilities for {env_name}")
        if not self.quiet:
            print(f"Fetching vulnerabilities from {env_name}...")
        
        env_config = self.config[env_name]
        scope_mode = env_config.get('scope_mode', 'management_zone')
        
        all_vulnerabilities = []
        
        if scope_mode == 'management_zone':
            mz_list = env_config.get('management_zones', [])
            self.logger.info(f"Using management zones: {mz_list}")
            
            for mz in mz_list:
                self.logger.debug(f"Querying management zone: {mz}")
                # Get all security problems (filtered by MZ in post-processing)
                vulns = api.getSecurityProblems()
                
                # Filter by management zone
                filtered_vulns = self._filter_by_management_zone(vulns, mz, api)
                all_vulnerabilities.extend(filtered_vulns)
        
        elif scope_mode == 'host_list':
            host_list = env_config.get('hosts', [])
            self.logger.info(f"Using host list with {len(host_list)} hosts")
            
            for host_id in host_list:
                self.logger.debug(f"Querying host: {host_id}")
                # Get host details and related vulnerabilities
                vulns = self._get_vulnerabilities_for_host(host_id, api)
                all_vulnerabilities.extend(vulns)
        
        # Enrich vulnerabilities with details
        enriched_vulns = self._enrich_vulnerabilities(all_vulnerabilities, api)
        
        self.logger.info(f"Found {len(enriched_vulns)} vulnerabilities in {env_name}")
        if not self.quiet:
            print(f"  → Found {len(enriched_vulns)} vulnerabilities\n")
        
        return enriched_vulns
    
    def _fetch_vulnerability_details(self, vuln_id: str, api: DynatraceApi) -> Optional[Dict]:
        """Fetch details for a single vulnerability (used in parallel execution)"""
        try:
            return api.getSecurityProblemDetails(vuln_id)
        except Exception as e:
            self.logger.error(f"Failed to fetch details for vulnerability {vuln_id}: {e}")
            return None
    
    def _fetch_vulnerability_details_parallel(self, vuln_ids: List[str], api: DynatraceApi) -> Dict[str, Dict]:
        """Fetch vulnerability details in parallel using thread pool"""
        details_map = {}
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_id = {executor.submit(self._fetch_vulnerability_details, vuln_id, api): vuln_id 
                           for vuln_id in vuln_ids}
            
            # Collect results as they complete
            for future in as_completed(future_to_id):
                vuln_id = future_to_id[future]
                try:
                    details = future.result()
                    if details:
                        details_map[vuln_id] = details
                except Exception as e:
                    self.logger.error(f"Exception fetching vulnerability {vuln_id}: {e}")
        
        return details_map
    
    def _filter_by_management_zone(self, vulnerabilities: List[Dict], mz_name: str, api: DynatraceApi) -> List[Dict]:
        """Filter vulnerabilities by management zone (using parallel fetching)"""
        filtered = []
        
        # Collect all vulnerability IDs
        vuln_ids = [vuln['securityProblemId'] for vuln in vulnerabilities]
        
        # Fetch all details in parallel
        details_map = self._fetch_vulnerability_details_parallel(vuln_ids, api)
        
        # Filter by management zone
        for vuln in vulnerabilities:
            vuln_id = vuln['securityProblemId']
            if vuln_id in details_map:
                details = details_map[vuln_id]
                if 'managementZones' in details:
                    vuln_mzs = [mz['name'] for mz in details.get('managementZones', [])]
                    if mz_name in vuln_mzs:
                        filtered.append(vuln)
        
        return filtered
    
    def _get_vulnerabilities_for_host(self, host_id: str, api: DynatraceApi) -> List[Dict]:
        """Get all vulnerabilities affecting a specific host (using parallel fetching)"""
        # Get security problems and filter by affected entities
        all_vulns = api.getSecurityProblems()
        host_vulns = []
        
        # Collect all vulnerability IDs
        vuln_ids = [vuln['securityProblemId'] for vuln in all_vulns]
        
        # Fetch all details in parallel
        details_map = self._fetch_vulnerability_details_parallel(vuln_ids, api)
        
        # Filter by host
        for vuln in all_vulns:
            vuln_id = vuln['securityProblemId']
            if vuln_id in details_map:
                details = details_map[vuln_id]
                # Check if host is in relatedEntities.hosts
                if 'relatedEntities' in details and 'hosts' in details['relatedEntities']:
                    for host_entity in details['relatedEntities']['hosts']:
                        # The host entity structure is: {"id": "HOST-xxx", "numberOfAffectedEntities": N, "affectedEntities": ["PGI-xxx", ...]}
                        if host_entity.get('id') == host_id:
                            host_vulns.append(vuln)
                            break
        
        return host_vulns
    
    def _enrich_vulnerabilities(self, vulnerabilities: List[Dict], api: DynatraceApi) -> List[Dict]:
        """Enrich vulnerabilities with full details (using parallel fetching) and apply exclusions"""
        enriched = []
        
        # Collect all vulnerability IDs
        vuln_ids = [vuln['securityProblemId'] for vuln in vulnerabilities]
        
        # Fetch all details in parallel
        details_map = self._fetch_vulnerability_details_parallel(vuln_ids, api)
        
        # Merge basic info with details and filter excluded CVEs
        for vuln in vulnerabilities:
            vuln_id = vuln['securityProblemId']
            if vuln_id in details_map:
                enriched_vuln = {**vuln, **details_map[vuln_id]}
                
                # Check if vulnerability should be excluded based on CVE
                cve_ids = enriched_vuln.get('cveIds', [])
                if any(cve in self.excluded_cves for cve in cve_ids):
                    self.logger.info(f"Excluding vulnerability {vuln_id} - CVE in exclusion list: {cve_ids}")
                    continue
                
                enriched.append(enriched_vuln)
                enriched.append(enriched_vuln)
            else:
                self.logger.warning(f"Failed to enrich vulnerability {vuln_id}")
                enriched.append(vuln)
        
        return enriched
    
    def _compare_vulnerabilities(self, cert_vulns: List[Dict], prod_vulns: List[Dict]) -> Dict:
        """Compare certification and production vulnerabilities"""
        self.logger.info("Performing comparative analysis")
        if not self.quiet:
            print(f"{Colors.BOLD}Comparing Certification vs Production...{Colors.END}")
        
        # Extract CVE IDs for comparison
        cert_cves = set()
        prod_cves = set()
        
        for vuln in cert_vulns:
            if 'cveIds' in vuln:
                # cveIds is an array, add all CVEs
                for cve_id in vuln['cveIds']:
                    cert_cves.add(cve_id)
        
        for vuln in prod_vulns:
            if 'cveIds' in vuln:
                # cveIds is an array, add all CVEs
                for cve_id in vuln['cveIds']:
                    prod_cves.add(cve_id)
        
        # Calculate differences
        new_cves = cert_cves - prod_cves
        resolved_cves = prod_cves - cert_cves
        common_cves = cert_cves & prod_cves
        
        # Analyze severity changes per PGI
        severity_regression_result = self._check_severity_regression_per_pgi(cert_vulns, prod_vulns)
        
        # Check for vulnerable function usage changes per PGI
        vuln_function_regression_result = self._check_vulnerable_function_regression_per_pgi(cert_vulns, prod_vulns)
        
        # Check if new vulnerabilities should be considered a regression based on threshold
        max_new_vulns = self.thresholds.get('max_new_vulnerabilities', -1)
        new_vuln_regression = False
        if max_new_vulns >= 0 and len(new_cves) > max_new_vulns:
            new_vuln_regression = True
        
        comparison = {
            'new_vulnerabilities': list(new_cves),
            'new_vulnerabilities_count': len(new_cves),
            'resolved_vulnerabilities': list(resolved_cves),
            'resolved_vulnerabilities_count': len(resolved_cves),
            'common_vulnerabilities': list(common_cves),
            'common_vulnerabilities_count': len(common_cves),
            'severity_regression': severity_regression_result['has_regression'],
            'severity_regression_details': severity_regression_result['regressions'],
            'vulnerable_function_regression': vuln_function_regression_result['has_regression'],
            'vulnerable_function_regression_details': vuln_function_regression_result['regressions'],
            'has_regression': new_vuln_regression or severity_regression_result['has_regression'] or vuln_function_regression_result['has_regression']
        }
        
        if not self.quiet:
            print(f"  New vulnerabilities: {Colors.RED if len(new_cves) > 0 else Colors.GREEN}{len(new_cves)}{Colors.END}")
            print(f"  Resolved vulnerabilities: {Colors.GREEN}{len(resolved_cves)}{Colors.END}")
            print(f"  Common vulnerabilities: {len(common_cves)}")
            print(f"  Severity regressions: {Colors.RED if severity_regression_result['has_regression'] else Colors.GREEN}{len(severity_regression_result['regressions'])}{Colors.END}")
            print(f"  Vulnerable function regressions: {Colors.RED if vuln_function_regression_result['has_regression'] else Colors.GREEN}{len(vuln_function_regression_result['regressions'])}{Colors.END}\n")
        
        return comparison
    
    def _check_severity_regression_per_pgi(self, cert_vulns: List[Dict], prod_vulns: List[Dict]) -> Dict:
        """Check if any vulnerability has increased in severity within the filtered scope"""
        # Build severity map for production CVEs (within scope): {CVE: severity}
        # Note: Vulnerabilities are already filtered by MZ/Host List in _fetch_vulnerabilities
        prod_severity_map = {}
        for vuln in prod_vulns:
            cve_ids = vuln.get('cveIds', [])
            if not cve_ids:
                continue
            
            risk_level = vuln.get('riskAssessment', {}).get('riskLevel', 'NONE')
            
            # Track the highest severity seen for each CVE in production scope
            for cve in cve_ids:
                if cve not in prod_severity_map:
                    prod_severity_map[cve] = risk_level
                else:
                    # Keep the highest severity if CVE appears multiple times
                    severity_order = {'NONE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
                    if severity_order.get(risk_level, 0) > severity_order.get(prod_severity_map[cve], 0):
                        prod_severity_map[cve] = risk_level
        
        # Check if any cert vulnerability has higher severity than in production scope
        severity_order = {'NONE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        regressions = []
        
        # Track highest severity per CVE in certification
        cert_severity_map = {}
        for vuln in cert_vulns:
            cve_ids = vuln.get('cveIds', [])
            if not cve_ids:
                continue
            
            cert_risk_level = vuln.get('riskAssessment', {}).get('riskLevel', 'NONE')
            
            # Track the highest severity seen for each CVE in certification scope
            for cve in cve_ids:
                if cve not in cert_severity_map:
                    cert_severity_map[cve] = cert_risk_level
                else:
                    if severity_order.get(cert_risk_level, 0) > severity_order.get(cert_severity_map[cve], 0):
                        cert_severity_map[cve] = cert_risk_level
        
        # Compare CVE severities between environments
        for cve, cert_severity in cert_severity_map.items():
            if cve in prod_severity_map:
                prod_severity = prod_severity_map[cve]
                
                # Check if severity_regression check is excluded for this severity level
                severity_exclusion_list = self.severity_exclusions.get(cert_severity, [])
                if 'severity_regression' in severity_exclusion_list:
                    self.logger.debug(f"Skipping severity regression check for {cve} at {cert_severity} severity")
                    continue
                
                # Check if severity increased in certification scope vs production scope
                if severity_order.get(cert_severity, 0) > severity_order.get(prod_severity, 0):
                    regression_info = {
                        'cve': cve,
                        'prod_severity': prod_severity,
                        'cert_severity': cert_severity,
                        'scope': 'Filtered by MZ/Host List'
                    }
                    regressions.append(regression_info)
                    self.logger.warning(
                        f"Severity regression for {cve} in filtered scope: "
                        f"{prod_severity} → {cert_severity}"
                    )
        
        return {
            'has_regression': len(regressions) > 0,
            'regressions': regressions
        }
    
    def _check_vulnerable_function_regression_per_pgi(self, cert_vulns: List[Dict], prod_vulns: List[Dict]) -> Dict:
        """Check if vulnerable functions are now in use when they weren't before within the filtered scope"""
        # Build vulnerable function map for production CVEs (within scope): {CVE: usage}
        # Note: Vulnerabilities are already filtered by MZ/Host List in _fetch_vulnerabilities
        prod_function_map = {}
        for vuln in prod_vulns:
            cve_ids = vuln.get('cveIds', [])
            if not cve_ids:
                continue
            
            vuln_func_usage = vuln.get('riskAssessment', {}).get('vulnerableFunctionUsage', 'NOT_AVAILABLE')
            
            # Track the "worst" usage state for each CVE in production scope
            # Priority: IN_USE > NOT_AVAILABLE > NOT_IN_USE
            for cve in cve_ids:
                if cve not in prod_function_map:
                    prod_function_map[cve] = vuln_func_usage
                else:
                    # Keep IN_USE if found anywhere, otherwise keep NOT_AVAILABLE over NOT_IN_USE
                    current = prod_function_map[cve]
                    if vuln_func_usage == 'IN_USE':
                        prod_function_map[cve] = 'IN_USE'
                    elif vuln_func_usage == 'NOT_AVAILABLE' and current == 'NOT_IN_USE':
                        prod_function_map[cve] = 'NOT_AVAILABLE'
        
        # Check for regressions in certification scope
        regressions = []
        
        # Track the "worst" usage state per CVE in certification
        cert_function_map = {}
        for vuln in cert_vulns:
            cve_ids = vuln.get('cveIds', [])
            if not cve_ids:
                continue
            
            cert_usage = vuln.get('riskAssessment', {}).get('vulnerableFunctionUsage', 'NOT_AVAILABLE')
            
            for cve in cve_ids:
                if cve not in cert_function_map:
                    cert_function_map[cve] = cert_usage
                else:
                    current = cert_function_map[cve]
                    if cert_usage == 'IN_USE':
                        cert_function_map[cve] = 'IN_USE'
                    elif cert_usage == 'NOT_AVAILABLE' and current == 'NOT_IN_USE':
                        cert_function_map[cve] = 'NOT_AVAILABLE'
        
        # Compare CVE vulnerable function usage between environments
        for cve, cert_usage in cert_function_map.items():
            if cve in prod_function_map:
                prod_usage = prod_function_map[cve]
                
                # Regression if cert has IN_USE when prod had NOT_IN_USE
                if cert_usage == 'IN_USE' and prod_usage == 'NOT_IN_USE':
                    regression_info = {
                        'cve': cve,
                        'prod_usage': prod_usage,
                        'cert_usage': cert_usage,
                        'scope': 'Filtered by MZ/Host List'
                    }
                    regressions.append(regression_info)
                    self.logger.warning(
                        f"Vulnerable function regression for {cve} in filtered scope: "
                        f"{prod_usage} → {cert_usage}"
                    )
        
        return {
            'has_regression': len(regressions) > 0,
            'regressions': regressions
        }
        
        return {
            'has_regression': len(regressions) > 0,
            'regressions': regressions
        }
    
    def _make_decision(self, results: Dict) -> Dict:
        """Make GO/NO-GO decision based on assessment results"""
        self.logger.info("Making GO/NO-GO decision")
        if not self.quiet:
            print(f"{Colors.BOLD}=== Decision Analysis ==={Colors.END}\n")
        
        cert_vulns = results['certification']['vulnerabilities']
        reasons = []
        
        # Analyze certification environment
        critical_high_count = self._count_high_severity_vulnerabilities(cert_vulns)
        vuln_func_in_use = self._count_vulnerable_functions_in_use(cert_vulns)
        max_allowed = self.thresholds.get('max_allowed_severity', 'HIGH')
        
        if not self.quiet:
            print(f"{Colors.BOLD}Certification Environment:{Colors.END}")
            print(f"  Total vulnerabilities: {len(cert_vulns)}")
            print(f"  Vulnerabilities above {max_allowed} severity: {Colors.RED if critical_high_count > 0 else Colors.GREEN}{critical_high_count}{Colors.END}")
            print(f"  Vulnerable functions in use: {Colors.RED if vuln_func_in_use > 0 else Colors.GREEN}{vuln_func_in_use}{Colors.END}\n")
            
            # Display vulnerability digest
            self._display_vulnerability_digest(cert_vulns)
        
        # Base decision criteria
        has_critical_high = critical_high_count > 0
        has_vuln_func_issues = vuln_func_in_use > 0
        
        if has_critical_high:
            max_allowed = self.thresholds.get('max_allowed_severity', 'HIGH')
            reasons.append(f"Found {critical_high_count} vulnerabilities above {max_allowed} severity threshold")
        
        if has_vuln_func_issues:
            reasons.append(f"Found {vuln_func_in_use} vulnerabilities with vulnerable functions in use or assessment unavailable")
        
        # Compare mode additional checks
        if self.mode == 'compare':
            comparison = results['comparison']
            has_regression = comparison['has_regression']
            
            # Check max_new_vulnerabilities threshold
            max_new_vulns = self.thresholds.get('max_new_vulnerabilities', -1)
            new_vuln_count = comparison['new_vulnerabilities_count']
            exceeds_new_vuln_threshold = False
            
            if max_new_vulns >= 0 and new_vuln_count > max_new_vulns:
                exceeds_new_vuln_threshold = True
                has_regression = True  # Treat as regression
            
            if not self.quiet:
                print(f"{Colors.BOLD}Comparative Analysis:{Colors.END}")
                print(f"  Regression detected: {Colors.RED if has_regression else Colors.GREEN}{has_regression}{Colors.END}")
                if max_new_vulns >= 0:
                    print(f"  New vulnerabilities: {new_vuln_count} (max allowed: {max_new_vulns})")
                print()
            
            if has_regression:
                # Only report new vulnerabilities if they exceed the threshold or if no threshold is set
                if exceeds_new_vuln_threshold:
                    reasons.append(f"Introduced {new_vuln_count} new vulnerabilities (max allowed: {max_new_vulns})")
                if comparison['severity_regression']:
                    reasons.append("Detected severity regression compared to production")
                if comparison['vulnerable_function_regression']:
                    reasons.append("Detected vulnerable function usage regression compared to production")
        
        # Make final decision
        if self.mode == 'evaluate':
            is_go = not has_critical_high and not has_vuln_func_issues
        else:  # compare mode
            has_regression = results['comparison']['has_regression']
            is_go = not has_critical_high and not has_vuln_func_issues and not has_regression
        
        decision = {
            'result': 'GO' if is_go else 'NO-GO',
            'timestamp': datetime.now().isoformat(),
            'mode': self.mode,
            'critical_high_count': critical_high_count,
            'vulnerable_functions_in_use': vuln_func_in_use,
            'reasons': reasons if not is_go else ["All criteria passed for production promotion"],
            'summary': self._generate_decision_summary(is_go, reasons)
        }
        
        if self.mode == 'compare':
            decision['regression_detected'] = results['comparison']['has_regression']
        
        # Display decision
        self._display_decision(decision)
        
        return decision
    
    def _count_high_severity_vulnerabilities(self, vulnerabilities: List[Dict]) -> int:
        """Count vulnerabilities at or above the configured max_allowed_severity threshold"""
        # Severity order for comparison
        severity_order = {'NONE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        max_allowed = self.thresholds.get('max_allowed_severity', 'HIGH')
        max_allowed_level = severity_order.get(max_allowed, 3)
        
        count = 0
        for vuln in vulnerabilities:
            risk_level = vuln.get('riskAssessment', {}).get('riskLevel', 'UNKNOWN')
            vuln_level = severity_order.get(risk_level, 0)
            
            # Count if vulnerability severity is above the allowed threshold
            if vuln_level > max_allowed_level:
                count += 1
        return count
    
    def _count_vulnerable_functions_in_use(self, vulnerabilities: List[Dict]) -> int:
        """Count vulnerabilities with vulnerable functions in use or unknown, respecting severity exclusions"""
        count = 0
        allow_vuln_func_severities = self.thresholds.get('allow_vulnerable_function_for_severities', [])
        
        for vuln in vulnerabilities:
            risk_level = vuln.get('riskAssessment', {}).get('riskLevel', 'UNKNOWN')
            vuln_func_usage = vuln.get('riskAssessment', {}).get('vulnerableFunctionUsage', 'NOT_AVAILABLE')
            
            # Check if vulnerable_function check is excluded for this severity
            severity_exclusion_list = self.severity_exclusions.get(risk_level, [])
            if 'vulnerable_function' in severity_exclusion_list:
                self.logger.debug(f"Skipping vulnerable function check for {risk_level} severity")
                continue
            
            # Check if this severity is allowed to have vulnerable functions in use
            if risk_level in allow_vuln_func_severities:
                self.logger.debug(f"Allowing vulnerable function for {risk_level} severity (threshold)")
                continue
            
            # Fail if IN_USE or if assessment is NOT_AVAILABLE (cannot assess with certainty)
            if vuln_func_usage in ['IN_USE', 'NOT_AVAILABLE']:
                count += 1
        return count
    
    def _display_vulnerability_digest(self, vulnerabilities: List[Dict]):
        """Display a colored digest of vulnerabilities"""
        if self.quiet:
            return
        print(f"{Colors.BOLD}Vulnerability Digest:{Colors.END}\n")
        
        if not vulnerabilities:
            print(f"  {Colors.GREEN}No vulnerabilities found{Colors.END}\n")
            return
        
        for vuln in vulnerabilities:
            cve_ids = vuln.get('cveIds', [])
            vuln_name = vuln.get('title', cve_ids[0] if cve_ids else 'Unknown')
            risk_score = vuln.get('riskAssessment', {}).get('riskScore', 'N/A')
            risk_level = vuln.get('riskAssessment', {}).get('riskLevel', 'UNKNOWN')
            vuln_func = vuln.get('riskAssessment', {}).get('vulnerableFunctionUsage', 'NOT_AVAILABLE')
            
            # Format CVE IDs display
            if cve_ids:
                cve_display = ', '.join(cve_ids)
            else:
                cve_display = f"{Colors.ORANGE}Unknown CVE{Colors.END}"
            
            print(f"  • {Colors.RED}{vuln_name}{Colors.END}")
            print(f"    CVE: {cve_display}")
            print(f"    Davis Security Score: {Colors.ORANGE}{risk_score}{Colors.END} | Severity: {risk_level}")
            print(f"    Vulnerable Function: {vuln_func}")
            print()
    
    def _generate_decision_summary(self, is_go: bool, reasons: List[str]) -> str:
        """Generate human-readable decision summary"""
        if is_go:
            summary = "✓ GO Decision: The certification environment meets all criteria for production promotion.\n"
            summary += "  All security checks passed successfully."
        else:
            summary = "✗ NO-GO Decision: The certification environment does not meet criteria for production promotion.\n"
            summary += "  Reasons:\n"
            for reason in reasons:
                summary += f"    - {reason}\n"
        
        return summary
    
    def _display_decision(self, decision: Dict):
        """Display the final decision with color"""
        if self.quiet:
            return  # Skip display in quiet mode
        
        result = decision['result']
        
        if result == 'GO':
            print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.END}")
            print(f"{Colors.BOLD}{Colors.GREEN}DECISION: GO ✓{Colors.END}")
            print(f"{Colors.BOLD}{Colors.GREEN}{'='*60}{Colors.END}\n")
        else:
            print(f"\n{Colors.BOLD}{Colors.RED}{'='*60}{Colors.END}")
            print(f"{Colors.BOLD}{Colors.RED}DECISION: NO-GO ✗{Colors.END}")
            print(f"{Colors.BOLD}{Colors.RED}{'='*60}{Colors.END}\n")
        
        print(decision['summary'])

class ReportGenerator:
    """Generates assessment reports in various formats"""
    
    def __init__(self, results: Dict, output_format: str = 'json'):
        self.results = results
        self.output_format = output_format.lower()
    
    def generate_report(self, output_file: str):
        """Generate and save report"""
        if self.output_format == 'json':
            self._generate_json_report(output_file)
        elif self.output_format == 'csv':
            self._generate_csv_report(output_file)
        else:
            raise ValueError(f"Unsupported output format: {self.output_format}")
        
        print(f"\n{Colors.GREEN}Report generated: {output_file}{Colors.END}\n")
    
    def _generate_json_report(self, output_file: str):
        """Generate JSON report with full vulnerability details"""
        report = {
            'assessment_info': {
                'mode': self.results['mode'],
                'timestamp': self.results['timestamp'],
                'decision': self.results['decision']['result'],
                'summary': self.results['decision']['summary']
            },
            'certification_environment': self._format_environment_data(
                self.results['certification']['vulnerabilities']
            )
        }
        
        if self.results['mode'] == 'compare':
            report['production_environment'] = self._format_environment_data(
                self.results['production']['vulnerabilities']
            )
            report['comparison'] = self.results['comparison']
        
        report['decision_details'] = self.results['decision']
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    
    def _generate_csv_report(self, output_file: str):
        """Generate CSV report with flattened vulnerability data"""
        cert_vulns = self.results['certification']['vulnerabilities']
        
        if not cert_vulns:
            # Create empty CSV with headers
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Environment', 'CVE_ID', 'Title', 'Risk_Level', 'Risk_Score', 
                               'Vulnerable_Function_Usage', 'Affected_Entities', 'Management_Zones'])
            return
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Headers
            writer.writerow([
                'Environment', 'CVE_ID', 'Title', 'Risk_Level', 'Risk_Score',
                'Vulnerable_Function_Usage', 'Technology', 'Package_Name',
                'Affected_Entities', 'Management_Zones', 'Status',
                'First_Seen', 'Last_Updated'
            ])
            
            # Certification vulnerabilities
            for vuln in cert_vulns:
                self._write_vulnerability_row(writer, vuln, 'CERTIFICATION')
            
            # Production vulnerabilities (if compare mode)
            if self.results['mode'] == 'compare':
                prod_vulns = self.results['production']['vulnerabilities']
                for vuln in prod_vulns:
                    self._write_vulnerability_row(writer, vuln, 'PRODUCTION')
    
    def _write_vulnerability_row(self, writer, vuln: Dict, env: str):
        """Write a single vulnerability row to CSV"""
        risk_assessment = vuln.get('riskAssessment', {})
        
        # Extract affected entities
        affected_entities = []
        if 'affectedEntities' in vuln:
            for entity in vuln['affectedEntities']:
                affected_entities.append(entity.get('name', entity.get('entityId', {}).get('id', 'Unknown')))
        
        # Extract management zones
        mz_list = []
        if 'managementZones' in vuln:
            mz_list = [mz.get('name', 'Unknown') for mz in vuln['managementZones']]
        
        writer.writerow([
            env,
            ','.join(vuln.get('cveIds', [])) if vuln.get('cveIds') else 'N/A',
            vuln.get('title', 'Unknown'),
            risk_assessment.get('riskLevel', 'UNKNOWN'),
            risk_assessment.get('riskScore', 'N/A'),
            risk_assessment.get('vulnerableFunctionUsage', 'NOT_AVAILABLE'),
            vuln.get('technology', 'Unknown'),
            vuln.get('packageName', 'Unknown'),
            '; '.join(affected_entities),
            '; '.join(mz_list),
            vuln.get('status', 'UNKNOWN'),
            vuln.get('firstSeenTimestamp', 'N/A'),
            vuln.get('lastUpdatedTimestamp', 'N/A')
        ])
    
    def _format_environment_data(self, vulnerabilities: List[Dict]) -> Dict:
        """Format vulnerability data with full metadata"""
        formatted_vulns = []
        
        for vuln in vulnerabilities:
            formatted_vuln = {
                'vulnerability_id': vuln.get('securityProblemId', 'Unknown'),
                'cve_ids': vuln.get('cveIds', []),
                'title': vuln.get('title', 'Unknown'),
                'status': vuln.get('status', 'UNKNOWN'),
                'risk_assessment': vuln.get('riskAssessment', {}),
                'technology': vuln.get('technology', 'Unknown'),
                'package_name': vuln.get('packageName', 'Unknown'),
                'vulnerable_component': vuln.get('vulnerableComponent', 'Unknown'),
                'first_seen': vuln.get('firstSeenTimestamp', 'N/A'),
                'last_updated': vuln.get('lastUpdatedTimestamp', 'N/A'),
                'affected_entities': [],
                'management_zones': []
            }
            
            # Add affected entities with full details
            if 'affectedEntities' in vuln:
                for entity in vuln['affectedEntities']:
                    formatted_vuln['affected_entities'].append({
                        'id': entity.get('entityId', {}).get('id', 'Unknown'),
                        'name': entity.get('name', 'Unknown'),
                        'type': entity.get('entityId', {}).get('type', 'Unknown')
                    })
            
            # Add management zones
            if 'managementZones' in vuln:
                for mz in vuln['managementZones']:
                    formatted_vuln['management_zones'].append({
                        'id': mz.get('id', 'Unknown'),
                        'name': mz.get('name', 'Unknown')
                    })
            
            formatted_vulns.append(formatted_vuln)
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'vulnerabilities': formatted_vulns
        }

def load_config(config_file: str) -> Dict:
    """Load and validate YAML configuration"""
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
        
        # Validate required fields
        if 'mode' not in config:
            raise ValueError("Configuration must specify 'mode'")
        
        if config['mode'].lower() not in ['evaluate', 'compare']:
            raise ValueError("Mode must be 'evaluate' or 'compare'")
        
        if 'certification_environment' not in config:
            raise ValueError("Configuration must include 'certification_environment'")
        
        if config['mode'].lower() == 'compare' and 'production_environment' not in config:
            raise ValueError("Compare mode requires 'production_environment' configuration")
        
        return config
    
    except yaml.YAMLError as e:
        print(f"{Colors.RED}Error parsing YAML configuration: {e}{Colors.END}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{Colors.RED}Configuration file not found: {config_file}{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}Error loading configuration: {e}{Colors.END}")
        sys.exit(1)

def setup_logging(verbose: bool):
    """Configure logging based on verbosity level"""
    log_level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('production_promotion_check.log'),
            logging.StreamHandler(sys.stdout) if verbose else logging.NullHandler()
        ]
    )

def print_usage_guide():
    """Print comprehensive usage guide"""
    guide = f"""
{Colors.BOLD}{'='*80}
Production Promotion GO/NO-GO Assessment Tool
{'='*80}{Colors.END}

{Colors.BOLD}DESCRIPTION:{Colors.END}
    This tool evaluates security vulnerabilities to determine if an application
    in a certification environment is ready for production promotion.

{Colors.BOLD}MODES:{Colors.END}
    {Colors.BLUE}Evaluate Mode:{Colors.END}
        Standalone assessment of certification environment against security criteria
    
    {Colors.BLUE}Compare Mode:{Colors.END}
        Comparative assessment between certification and production environments
        Checks for regressions and new vulnerabilities

{Colors.BOLD}USAGE:{Colors.END}
    python production_promotion_check.py -c <config_file> [OPTIONS]

{Colors.BOLD}OPTIONS:{Colors.END}
    -c, --config FILE       Path to YAML configuration file (required)
    -o, --output FILE       Output report file path (default: report_<timestamp>.json)
    -f, --format FORMAT     Report format: json or csv (default: json)
    -m, --machine-readable  Output only machine-readable decision (GO or NO-GO)
    -v, --verbose           Enable detailed logging
    -h, --help             Show this help message

{Colors.BOLD}DECISION CRITERIA:{Colors.END}
    
    {Colors.GREEN}GO Decision:{Colors.END}
        ✓ No CRITICAL or HIGH severity vulnerabilities
        ✓ No vulnerabilities with vulnerable functions in use
        ✓ Vulnerable function usage can be assessed with certainty
        ✓ [Compare mode] No regression compared to production
    
    {Colors.RED}NO-GO Decision:{Colors.END}
        ✗ Any CRITICAL or HIGH severity vulnerabilities found
        ✗ Any vulnerability with vulnerable function in use
        ✗ Any vulnerability where vulnerable function usage cannot be assessed
        ✗ [Compare mode] Regression detected compared to production

{Colors.BOLD}CONFIGURATION:{Colors.END}
    See example configuration files:
        - config_evaluate_example.yaml (Evaluate mode)
        - config_compare_example.yaml (Compare mode)

{Colors.BOLD}EXAMPLES:{Colors.END}
    # Evaluate mode with JSON output
    python production_promotion_check.py -c config_evaluate.yaml

    # Compare mode with CSV output
    python production_promotion_check.py -c config_compare.yaml -f csv -o report.csv

    # Machine-readable output for CI/CD pipeline
    python production_promotion_check.py -c config.yaml -m

    # Verbose mode with detailed logging
    python production_promotion_check.py -c config.yaml -v

{Colors.BOLD}EXIT CODES:{Colors.END}
    0 - GO decision (ready for production)
    1 - NO-GO decision (not ready for production)
    2 - Error in execution

{'='*80}
"""
    print(guide)

def main():
    """Main entry point"""
    parser = ArgumentParser(
        description='Production Promotion GO/NO-GO Assessment',
        add_help=False
    )
    
    parser.add_argument('-c', '--config', dest='config_file',
                       help='Path to YAML configuration file', required=False)
    parser.add_argument('-o', '--output', dest='output_file',
                       help='Output report file path', required=False)
    parser.add_argument('-f', '--format', dest='output_format',
                       help='Report format (json or csv)', default='json')
    parser.add_argument('-m', '--machine-readable', dest='machine_readable',
                       help='Output only machine-readable decision (GO or NO-GO)', action='store_true')
    parser.add_argument('--exit-code', dest='use_exit_code',
                       help='Exit with code 1 on NO-GO, 0 on GO (default: enabled)', 
                       action='store_true', default=True)
    parser.add_argument('-v', '--verbose', dest='verbose',
                       help='Enable detailed logging', action='store_true')
    parser.add_argument('-h', '--help', action='store_true', dest='show_help',
                       help='Show usage guide')
    
    args = parser.parse_args()
    
    # Show help if requested or no config provided
    if args.show_help or not args.config_file:
        print_usage_guide()
        sys.exit(0 if args.show_help else 2)
    
    # Setup logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    try:
        # Load configuration
        config = load_config(args.config_file)
        logger.info(f"Loaded configuration from {args.config_file}")
        
        # Run assessment
        assessment = VulnerabilityAssessment(config, args.verbose, quiet=args.machine_readable)
        results = assessment.run_assessment()
        
        # Generate output file name if not provided
        if not args.output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            extension = 'json' if args.output_format == 'json' else 'csv'
            args.output_file = f"report_{timestamp}.{extension}"
        
        # Generate report (unless machine-readable mode)
        if not args.machine_readable:
            report_gen = ReportGenerator(results, args.output_format)
            report_gen.generate_report(args.output_file)
        
        # Output result
        decision_result = results['decision']['result']
        
        if args.machine_readable:
            # Simple machine-readable output: GO or NO-GO
            print(decision_result, flush=True)
        
        # Exit with appropriate code (if enabled)
        if args.use_exit_code:
            exit_code = 0 if decision_result == 'GO' else 1
        else:
            exit_code = 0
        
        logger.info(f"Assessment complete. Decision: {decision_result}, Exit code: {exit_code}")
        sys.exit(exit_code)
    
    except Exception as e:
        logger.error(f"Assessment failed: {e}", exc_info=True)
        print(f"\n{Colors.RED}Error: {e}{Colors.END}\n")
        sys.exit(2)

if __name__ == '__main__':
    main()
