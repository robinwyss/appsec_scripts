#!/usr/bin/env python3
"""
Automatic Dampening Parameter Optimization for HRP v2.0
Analyzes environment and recommends optimal dampening parameters.
"""

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from copy import deepcopy

logger = logging.getLogger(__name__)


class DampeningOptimizer:
    """
    Automatically optimizes HRP v2 dampening parameters for environment.
    
    Uses grid search to find optimal exponent and max_score parameters that:
    1. Place current score in actionable range (70-90, optimal ~80)
    2. Provide visible sensitivity (8-15 point reduction for top 5 fixes)
    3. Avoid saturation (no components at 95+)
    4. Match environment complexity
    """
    
    def __init__(self, report_data: dict, config, calculator):
        """
        Initialize optimizer with assessment data.
        
        Args:
            report_data: Complete ASTRA report data from JSON
            config: AstraConfig instance
            calculator: RiskCalculator instance for recalculation
        """
        self.report_data = report_data
        self.config = config
        self.calculator = calculator
        self.original_exponent = config.get('hrp_v2.dampening_exponent', 0.75)
        self.original_max_score = config.get('hrp_v2.max_theoretical_score', 300)
        
    def analyze_environment(self) -> Dict[str, Any]:
        """
        Analyze environment complexity and current saturation.
        
        Returns:
            Dictionary with environment metrics:
            - total_vulnerabilities: Total vulnerability count
            - severity_distribution: Breakdown by severity
            - saturated_components: List of components at 90%+
            - current_score: Current overall risk score
            - entity_count: Number of entities assessed
        """
        overall = self.report_data.get('overall_risk', {})
        components = overall.get('components', {})
        summary = self.report_data.get('summary', {})
        
        # Identify saturated components (90%+ score)
        saturated = []
        for component, value in components.items():
            if isinstance(value, (int, float)) and value >= 90:
                saturated.append(component)
        
        return {
            'total_vulnerabilities': summary.get('total_vulnerabilities', 0),
            'severity_distribution': summary.get('by_severity', {}),
            'saturated_components': saturated,
            'current_score': overall.get('score', 0),
            'entity_count': summary.get('total_entities', 0),
            'current_rating': overall.get('rating', 'UNKNOWN')
        }
    
    def identify_top_vulnerabilities(self, n: int = 5) -> List[str]:
        """
        Get top N vulnerability IDs by impact/Davis score.
        
        Args:
            n: Number of top vulnerabilities to identify
            
        Returns:
            List of vulnerability IDs (securityProblemId)
        """
        priorities = self.report_data.get('remediation_priorities', [])
        
        # Sort by Davis score and take top N
        sorted_vulns = sorted(
            priorities,
            key=lambda v: v.get('davis_score', 0),
            reverse=True
        )[:n]
        
        return [v.get('vulnerability_id') or v.get('securityProblemId') 
                for v in sorted_vulns]
    
    def simulate_with_params(self, 
                            exponent: float, 
                            max_score: int,
                            exclude_vuln_ids: Optional[List[str]] = None) -> Tuple[float, Dict]:
        """
        Recalculate overall risk with different parameters.
        
        Args:
            exponent: Dampening exponent to test
            max_score: Max theoretical score to test
            exclude_vuln_ids: Optional list of vulnerability IDs to exclude
            
        Returns:
            Tuple of (overall_score, components_dict)
        """
        # Temporarily override config parameters
        original_exp = self.config.config.get('hrp_v2', {}).get('dampening_exponent')
        original_max = self.config.config.get('hrp_v2', {}).get('max_theoretical_score')
        
        try:
            # Set test parameters
            if 'hrp_v2' not in self.config.config:
                self.config.config['hrp_v2'] = {}
            self.config.config['hrp_v2']['dampening_exponent'] = exponent
            self.config.config['hrp_v2']['max_theoretical_score'] = max_score
            
            # Create filtered data if exclusions provided
            test_data = deepcopy(self.report_data)
            
            # Reconstruct security_problems from entities (JSON report format)
            all_vulnerabilities = []
            seen_vuln_ids = set()
            
            for entity in test_data.get('entities', []):
                for vuln in entity.get('vulnerabilities', []):
                    vuln_id = vuln.get('securityProblemId') or vuln.get('vulnerability_id')
                    if vuln_id and vuln_id not in seen_vuln_ids:
                        seen_vuln_ids.add(vuln_id)
                        all_vulnerabilities.append(vuln)
            
            # Filter if exclusions provided
            if exclude_vuln_ids:
                all_vulnerabilities = [
                    v for v in all_vulnerabilities
                    if (v.get('securityProblemId') not in exclude_vuln_ids and
                        v.get('vulnerability_id') not in exclude_vuln_ids)
                ]
            
            # Build data structure that _calculate_hrp_v2_risk expects
            calc_data = {
                'security_problems': all_vulnerabilities,
                'process_groups': [],  # Not needed for overall calculation
                'hosts': []
            }
            
            # Calculate HRP v2 risk with the test data
            result = self.calculator._calculate_hrp_v2_risk(calc_data)
            
            return result.get('score', 0), result.get('components', {})
            
        finally:
            # Restore original parameters
            if original_exp is not None:
                self.config.config['hrp_v2']['dampening_exponent'] = original_exp
            if original_max is not None:
                self.config.config['hrp_v2']['max_theoretical_score'] = original_max
    
    def find_optimal_params(self) -> Dict[str, Any]:
        """
        Grid search to find optimal dampening parameters.
        
        Tests combinations of exponents and max scores to find the best
        configuration based on fitness criteria:
        - Current score in 70-90 range (optimal: 80)
        - Score reduction of 8-15 points for top 5 fixes (optimal: 12)
        - No saturated components (95%+)
        
        Returns:
            Dictionary with:
            - exponent: Optimal exponent value
            - max_score: Optimal max score value
            - current_score: Projected current score
            - fixed_score: Score after fixing top 5
            - reduction: Point reduction from fixes
            - fitness: Fitness score (lower is better)
            - all_results: List of all tested combinations
        """
        logger.info("Starting dampening parameter optimization...")
        
        # Define search space
        exponents = [0.55, 0.60, 0.65, 0.70, 0.75]
        max_scores = [300, 400, 500, 600, 800]
        
        top_vulns = self.identify_top_vulnerabilities(5)
        logger.info(f"Identified {len(top_vulns)} top vulnerabilities for sensitivity test")
        
        best_params = None
        best_fitness = float('inf')
        results = []
        
        total_combinations = len(exponents) * len(max_scores)
        logger.info(f"Testing {total_combinations} parameter combinations...")
        
        for idx, exp in enumerate(exponents):
            for max_score in max_scores:
                # Calculate current score with these params
                current, current_components = self.simulate_with_params(exp, max_score)
                
                # Calculate score after fixing top 5
                fixed, fixed_components = self.simulate_with_params(
                    exp, max_score, top_vulns
                )
                
                # Check for saturation
                saturated_count = sum(
                    1 for v in current_components.values()
                    if isinstance(v, (int, float)) and v >= 95
                )
                
                # Evaluate fitness
                reduction = current - fixed
                fitness = self._evaluate_fitness(
                    current, fixed, saturated_count
                )
                
                result = {
                    'exponent': exp,
                    'max_score': max_score,
                    'current_score': round(current, 2),
                    'fixed_score': round(fixed, 2),
                    'reduction': round(reduction, 2),
                    'saturated_components': saturated_count,
                    'fitness': round(fitness, 2)
                }
                results.append(result)
                
                if fitness < best_fitness:
                    best_fitness = fitness
                    best_params = result.copy()
        
        # Sort results by fitness
        results.sort(key=lambda x: x['fitness'])
        best_params['all_results'] = results
        
        logger.info(f"Optimization complete. Best fitness: {best_fitness:.2f}")
        logger.info(f"Optimal parameters: exponent={best_params['exponent']}, "
                   f"max_score={best_params['max_score']}")
        
        return best_params
    
    def _evaluate_fitness(self, 
                         current_score: float, 
                         fixed_score: float,
                         saturated_count: int) -> float:
        """
        Score parameter combination (lower is better).
        
        Fitness criteria:
        1. Current score in 70-90 range (optimal: 80)
        2. Score reduction of 8-15 points (optimal: 12)
        3. No saturated components (penalty: 20 per component)
        
        Args:
            current_score: Score with current vulnerabilities
            fixed_score: Score after fixing top 5 vulnerabilities
            saturated_count: Number of components at 95%+
            
        Returns:
            Fitness score (lower is better)
        """
        penalty = 0
        reduction = current_score - fixed_score
        
        # 1. Prefer current score in 70-90 range (optimal: 80)
        if current_score < 70:
            penalty += (70 - current_score) ** 2
        elif current_score > 90:
            penalty += (current_score - 90) ** 2
        else:
            # Bonus for being close to 80
            penalty -= abs(80 - current_score) * 0.5
        
        # 2. Prefer score reduction of 8-15 points (optimal: 12)
        if reduction < 8:
            penalty += (8 - reduction) ** 2 * 2  # Heavily penalize low sensitivity
        elif reduction > 15:
            penalty += (reduction - 15) ** 2
        else:
            # Bonus for being close to 12
            penalty -= abs(12 - reduction) * 0.5
        
        # 3. Penalize saturation
        penalty += saturated_count * 20
        
        return penalty
    
    def backup_config(self, reason: str = "auto-optimization") -> str:
        """
        Backup current config with meaningful name.
        
        Args:
            reason: Reason for backup (included in filename)
            
        Returns:
            Backup filename
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        exp = self.original_exponent
        max_s = self.original_max_score
        
        backup_name = f"config_backup_{timestamp}_{reason}_exp{exp}_max{max_s}.yaml"
        config_path = Path(self.config.config_path)
        backup_path = config_path.parent / backup_name
        
        shutil.copy(config_path, backup_path)
        logger.info(f"Config backed up to: {backup_name}")
        
        return backup_name
    
    def update_config(self, 
                     new_exp: float, 
                     new_max: int,
                     optimization_summary: str) -> None:
        """
        Update config with optimized parameters.
        
        Uses ruamel.yaml to preserve comments and formatting.
        
        Args:
            new_exp: New dampening exponent
            new_max: New max theoretical score
            optimization_summary: Summary text to add as comment
        """
        try:
            from ruamel.yaml import YAML
            yaml = YAML()
            yaml.preserve_quotes = True
            yaml.width = 4096  # Prevent line wrapping
            
            config_path = Path(self.config.config_path)
            
            with open(config_path, 'r') as f:
                config = yaml.load(f)
            
            # Update parameters
            if 'hrp_v2' not in config:
                config['hrp_v2'] = {}
            
            config['hrp_v2']['dampening_exponent'] = new_exp
            config['hrp_v2']['max_theoretical_score'] = new_max
            
            # Write back
            with open(config_path, 'w') as f:
                yaml.dump(config, f)
            
            logger.info(f"Config updated: exponent={new_exp}, max_score={new_max}")
            
        except ImportError:
            logger.warning("ruamel.yaml not available, using PyYAML (may lose formatting)")
            self._update_config_pyyaml(new_exp, new_max)
    
    def _update_config_pyyaml(self, new_exp: float, new_max: int) -> None:
        """Fallback config update using PyYAML."""
        import yaml
        
        config_path = Path(self.config.config_path)
        
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        if 'hrp_v2' not in config:
            config['hrp_v2'] = {}
        
        config['hrp_v2']['dampening_exponent'] = new_exp
        config['hrp_v2']['max_theoretical_score'] = new_max
        
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        logger.info(f"Config updated (PyYAML): exponent={new_exp}, max_score={new_max}")
    
    def generate_report(self, optimization_result: Dict[str, Any]) -> str:
        """
        Generate human-readable optimization report.
        
        Args:
            optimization_result: Result from find_optimal_params()
            
        Returns:
            Formatted report string
        """
        env = self.analyze_environment()
        
        report = []
        report.append("=" * 80)
        report.append("HRP v2.0 - Auto-Dampening Optimization Results")
        report.append("=" * 80)
        report.append("")
        
        # Environment analysis
        report.append("Environment Analysis:")
        report.append(f"  • Total vulnerabilities: {env['total_vulnerabilities']}")
        sev = env['severity_distribution']
        report.append(f"  • Severity: {sev.get('CRITICAL', 0)} CRITICAL, "
                     f"{sev.get('HIGH', 0)} HIGH, {sev.get('MEDIUM', 0)} MEDIUM, "
                     f"{sev.get('LOW', 0)} LOW")
        report.append(f"  • Current score: {env['current_score']:.2f} [{env['current_rating']}]")
        report.append(f"  • Saturated components: {len(env['saturated_components'])}")
        if env['saturated_components']:
            report.append(f"    ({', '.join(env['saturated_components'])})")
        report.append("")
        
        # Current vs Optimized
        report.append("Parameter Comparison:")
        report.append("┌" + "─" * 78 + "┐")
        report.append(f"│ {'Configuration':<25} │ {'Current':<15} │ {'Optimized':<15} │ {'Change':<15} │")
        report.append("├" + "─" * 78 + "┤")
        
        exp_change = f"{optimization_result['exponent'] - self.original_exponent:+.2f}"
        report.append(f"│ {'Dampening Exponent':<25} │ {self.original_exponent:<15.2f} │ "
                     f"{optimization_result['exponent']:<15.2f} │ {exp_change:<15} │")
        
        max_change = f"{optimization_result['max_score'] - self.original_max_score:+d}"
        report.append(f"│ {'Max Theoretical Score':<25} │ {self.original_max_score:<15d} │ "
                     f"{optimization_result['max_score']:<15d} │ {max_change:<15} │")
        
        report.append("└" + "─" * 78 + "┘")
        report.append("")
        
        # Impact analysis
        report.append("Projected Impact:")
        report.append(f"  • Current score:        {optimization_result['current_score']:.2f}")
        report.append(f"  • After fixing top 5:   {optimization_result['fixed_score']:.2f}")
        report.append(f"  • Score reduction:      -{optimization_result['reduction']:.2f} points")
        report.append(f"  • Saturated components: {optimization_result['saturated_components']}")
        report.append(f"  • Fitness score:        {optimization_result['fitness']:.2f} (lower is better)")
        report.append("")
        
        # Rationale
        report.append("Why These Parameters?")
        report.append(self._get_rationale(optimization_result, env))
        report.append("")
        
        # Top 5 alternatives
        report.append("Alternative Configurations (Top 5):")
        for idx, result in enumerate(optimization_result['all_results'][:5], 1):
            report.append(f"  {idx}. Exp={result['exponent']:.2f}, Max={result['max_score']}: "
                         f"Score {result['current_score']:.2f} → {result['fixed_score']:.2f} "
                         f"(-{result['reduction']:.2f}), Fitness={result['fitness']:.2f}")
        
        report.append("")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def _get_rationale(self, result: Dict[str, Any], env: Dict[str, Any]) -> str:
        """Generate explanation for parameter selection."""
        reasons = []
        
        vuln_count = env['total_vulnerabilities']
        
        # Exponent rationale
        if result['exponent'] < 0.65:
            reasons.append(f"  • Lower exponent ({result['exponent']}) for strong dampening "
                          f"with {vuln_count} vulnerabilities")
        elif result['exponent'] > 0.70:
            reasons.append(f"  • Higher exponent ({result['exponent']}) maintains sensitivity "
                          f"with moderate vulnerability count")
        else:
            reasons.append(f"  • Balanced exponent ({result['exponent']}) for {vuln_count} "
                          f"vulnerabilities")
        
        # Max score rationale
        if result['max_score'] >= 600:
            reasons.append(f"  • High max score ({result['max_score']}) provides headroom for growth")
        elif result['max_score'] <= 400:
            reasons.append(f"  • Lower max score ({result['max_score']}) keeps scores elevated")
        else:
            reasons.append(f"  • Moderate max score ({result['max_score']}) balances range")
        
        # Score placement
        if 70 <= result['current_score'] <= 90:
            reasons.append(f"  • Current score ({result['current_score']:.1f}) in optimal actionable range")
        
        # Sensitivity
        if 8 <= result['reduction'] <= 15:
            reasons.append(f"  • Good sensitivity: -{result['reduction']:.1f} points for top 5 fixes")
        
        # Saturation
        if result['saturated_components'] == 0:
            reasons.append("  • Eliminates score saturation (headroom for worse scenarios)")
        
        return "\n".join(reasons)
