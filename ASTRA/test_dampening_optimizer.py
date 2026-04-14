#!/usr/bin/env python3
"""
Unit tests for dampening_optimizer module.
"""

import unittest
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock
from dampening_optimizer import DampeningOptimizer


class TestDampeningOptimizer(unittest.TestCase):
    """Test suite for DampeningOptimizer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create mock report data
        self.report_data = {
            'overall_risk': {
                'score': 78.42,
                'rating': 'HIGH',
                'components': {
                    'vulnerability_risk': 100.0,
                    'supply_chain_risk': 45.0,
                    'topology_risk': 60.0,
                    'aging_penalty': 100.0
                }
            },
            'summary': {
                'total_vulnerabilities': 96,
                'by_severity': {
                    'CRITICAL': 0,
                    'HIGH': 28,
                    'MEDIUM': 50,
                    'LOW': 18
                },
                'total_entities': 5
            },
            'entities': [
                {
                    'entity_id': 'PG-001',
                    'entity_name': 'Test Process',
                    'vulnerabilities': [],
                    'vulnerability_count': 0
                }
            ],
            'remediation_priorities': [
                {
                    'vulnerability_id': 'VULN-001',
                    'securityProblemId': 'VULN-001',
                    'davis_score': 8.5
                },
                {
                    'vulnerability_id': 'VULN-002',
                    'securityProblemId': 'VULN-002',
                    'davis_score': 7.2
                }
            ]
        }
        
        # Create mock config
        self.config = Mock()
        self.config.config = {
            'hrp_v2': {
                'dampening_exponent': 0.75,
                'max_theoretical_score': 300
            }
        }
        self.config.get = Mock(side_effect=lambda key, default=None: {
            'hrp_v2.dampening_exponent': 0.75,
            'hrp_v2.max_theoretical_score': 300
        }.get(key, default))
        self.config.config_path = 'test_config.yaml'
        
        # Create mock calculator
        self.calculator = Mock()
        self.calculator._calculate_hrp_v2_risk = Mock(return_value={
            'score': 75.0,
            'components': {
                'vulnerability_risk': 80.0,
                'supply_chain_risk': 45.0,
                'topology_risk': 60.0,
                'aging_penalty': 90.0
            }
        })
        
        # Initialize optimizer
        self.optimizer = DampeningOptimizer(
            self.report_data,
            self.config,
            self.calculator
        )
    
    def test_initialization(self):
        """Test optimizer initializes correctly."""
        self.assertEqual(self.optimizer.original_exponent, 0.75)
        self.assertEqual(self.optimizer.original_max_score, 300)
        self.assertIsNotNone(self.optimizer.report_data)
    
    def test_analyze_environment(self):
        """Test environment analysis."""
        env = self.optimizer.analyze_environment()
        
        self.assertEqual(env['total_vulnerabilities'], 96)
        self.assertEqual(env['current_score'], 78.42)
        self.assertEqual(env['current_rating'], 'HIGH')
        self.assertEqual(len(env['saturated_components']), 2)  # vulnerability and aging
        self.assertIn('vulnerability_risk', env['saturated_components'])
        self.assertIn('aging_penalty', env['saturated_components'])
    
    def test_identify_top_vulnerabilities(self):
        """Test identification of top vulnerabilities."""
        top_vulns = self.optimizer.identify_top_vulnerabilities(n=2)
        
        self.assertEqual(len(top_vulns), 2)
        self.assertEqual(top_vulns[0], 'VULN-001')  # Highest Davis score
        self.assertEqual(top_vulns[1], 'VULN-002')
    
    def test_evaluate_fitness_optimal(self):
        """Test fitness evaluation for optimal parameters."""
        # Optimal scenario: score at 80, reduction of 12, no saturation
        fitness = self.optimizer._evaluate_fitness(80.0, 68.0, 0)
        
        # Should have low (good) fitness score
        self.assertLess(fitness, 5.0)
    
    def test_evaluate_fitness_saturated(self):
        """Test fitness evaluation with saturation."""
        # Same scores but with 2 saturated components
        fitness = self.optimizer._evaluate_fitness(80.0, 68.0, 2)
        
        # Should have high penalty (20 points per saturated component)
        self.assertGreaterEqual(fitness, 40.0)
    
    def test_evaluate_fitness_low_sensitivity(self):
        """Test fitness evaluation with low fix sensitivity."""
        # Only 3 point reduction (too low, target is 8-15)
        fitness = self.optimizer._evaluate_fitness(80.0, 77.0, 0)
        
        # Should be penalized for low sensitivity
        self.assertGreater(fitness, 10.0)
    
    def test_get_rationale(self):
        """Test rationale generation."""
        result = {
            'exponent': 0.65,
            'max_score': 500,
            'current_score': 75.0,
            'reduction': 12.0,
            'saturated_components': 0
        }
        env = {'total_vulnerabilities': 96}
        
        rationale = self.optimizer._get_rationale(result, env)
        
        self.assertIn('0.65', rationale)
        self.assertIn('500', rationale)
        self.assertIsInstance(rationale, str)
        self.assertGreater(len(rationale), 50)


class TestFitnessFunction(unittest.TestCase):
    """Test suite for fitness function evaluation."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Minimal setup just for fitness testing
        self.report_data = {
            'overall_risk': {'score': 70, 'rating': 'MEDIUM', 'components': {}},
            'summary': {'total_vulnerabilities': 50, 'by_severity': {}, 'total_entities': 1},
            'entities': [],
            'remediation_priorities': []
        }
        self.config = Mock()
        self.config.config = {'hrp_v2': {}}
        self.config.get = Mock(return_value=0.75)
        self.calculator = Mock()
        
        self.optimizer = DampeningOptimizer(
            self.report_data, self.config, self.calculator
        )
    
    def test_fitness_perfect_score(self):
        """Test fitness with perfect score placement and sensitivity."""
        # Score at 80 (optimal), reduction of 12 (optimal), no saturation
        fitness = self.optimizer._evaluate_fitness(80.0, 68.0, 0)
        
        # Should be negative (bonus) or very low
        self.assertLess(fitness, 5.0)
    
    def test_fitness_too_low_score(self):
        """Test fitness with score too low."""
        # Score at 60 (below 70 minimum)
        fitness = self.optimizer._evaluate_fitness(60.0, 50.0, 0)
        
        # Should be penalized
        self.assertGreater(fitness, 10.0)
    
    def test_fitness_too_high_score(self):
        """Test fitness with score too high."""
        # Score at 95 (above 90 maximum)
        fitness = self.optimizer._evaluate_fitness(95.0, 85.0, 0)
        
        # Should be penalized
        self.assertGreater(fitness, 10.0)
    
    def test_fitness_components(self):
        """Test that fitness function considers all components."""
        # Perfect score, perfect reduction, but saturation
        fitness_no_sat = self.optimizer._evaluate_fitness(80.0, 68.0, 0)
        fitness_with_sat = self.optimizer._evaluate_fitness(80.0, 68.0, 1)
        
        # Saturation should add 20 points penalty
        self.assertAlmostEqual(fitness_with_sat - fitness_no_sat, 20.0, delta=0.1)


if __name__ == '__main__':
    unittest.main()
