#!/usr/bin/env python3
"""
Test Suite for Production Promotion Check Tool
Executes test cases and validates functionality
"""

import subprocess
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    ORANGE = '\033[93m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

class TestCase:
    def __init__(self, test_id: str, name: str, config_file: str, expected_result: str, 
                 expected_conditions: List[str], description: str = ""):
        self.test_id = test_id
        self.name = name
        self.config_file = config_file
        self.expected_result = expected_result  # "GO" or "NO-GO"
        self.expected_conditions = expected_conditions
        self.description = description
        self.actual_result = None
        self.passed = None
        self.output = ""
        self.error = ""

class TestRunner:
    def __init__(self):
        self.test_cases: List[TestCase] = []
        self.results: Dict[str, List[TestCase]] = {
            'passed': [],
            'failed': [],
            'error': []
        }
        
    def add_test(self, test: TestCase):
        self.test_cases.append(test)
    
    def run_test(self, test: TestCase) -> bool:
        """Execute a single test case"""
        print(f"\n{Colors.BOLD}Running {test.test_id}: {test.name}{Colors.END}")
        print(f"Config: {test.config_file}")
        print(f"Expected: {test.expected_result}")
        
        config_path = f"tempconfig/{test.config_file}"
        if not os.path.exists(config_path):
            test.error = f"Config file not found: {config_path}"
            test.passed = False
            self.results['error'].append(test)
            print(f"{Colors.RED}✗ ERROR: {test.error}{Colors.END}")
            return False
        
        try:
            # Run the production promotion check
            cmd = ["python", "production_promotion_check.py", "-c", config_path]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            test.output = result.stdout
            test.error = result.stderr
            
            # Parse the decision from output
            if "DECISION: GO" in test.output:
                test.actual_result = "GO"
            elif "DECISION: NO-GO" in test.output:
                test.actual_result = "NO-GO"
            else:
                test.actual_result = "UNKNOWN"
                test.error = "Could not parse decision from output"
            
            # Validate expected result
            if test.actual_result == test.expected_result:
                # Check expected conditions
                conditions_met = all(
                    cond in test.output for cond in test.expected_conditions
                )
                
                if conditions_met:
                    test.passed = True
                    self.results['passed'].append(test)
                    print(f"{Colors.GREEN}✓ PASSED{Colors.END}")
                else:
                    test.passed = False
                    self.results['failed'].append(test)
                    missing = [c for c in test.expected_conditions if c not in test.output]
                    print(f"{Colors.ORANGE}✗ FAILED: Expected conditions not met{Colors.END}")
                    print(f"  Missing: {missing}")
            else:
                test.passed = False
                self.results['failed'].append(test)
                print(f"{Colors.RED}✗ FAILED: Expected {test.expected_result}, got {test.actual_result}{Colors.END}")
            
            return test.passed
            
        except subprocess.TimeoutExpired:
            test.error = "Test timeout (120s)"
            test.passed = False
            self.results['error'].append(test)
            print(f"{Colors.RED}✗ ERROR: Test timeout{Colors.END}")
            return False
        except Exception as e:
            test.error = str(e)
            test.passed = False
            self.results['error'].append(test)
            print(f"{Colors.RED}✗ ERROR: {e}{Colors.END}")
            return False
    
    def run_all_tests(self):
        """Execute all registered test cases"""
        print(f"\n{Colors.BOLD}{'='*60}")
        print(f"Production Promotion Check - Test Suite")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Tests: {len(self.test_cases)}")
        print(f"{'='*60}{Colors.END}\n")
        
        for test in self.test_cases:
            self.run_test(test)
        
        self.print_summary()
    
    def print_summary(self):
        """Print test execution summary"""
        total = len(self.test_cases)
        passed = len(self.results['passed'])
        failed = len(self.results['failed'])
        error = len(self.results['error'])
        
        print(f"\n{Colors.BOLD}{'='*60}")
        print("Test Summary")
        print(f"{'='*60}{Colors.END}")
        print(f"Total Tests:  {total}")
        print(f"{Colors.GREEN}Passed:       {passed}{Colors.END}")
        print(f"{Colors.RED}Failed:       {failed}{Colors.END}")
        print(f"{Colors.ORANGE}Errors:       {error}{Colors.END}")
        print(f"Success Rate: {(passed/total*100):.1f}%\n")
        
        if failed > 0:
            print(f"{Colors.RED}Failed Tests:{Colors.END}")
            for test in self.results['failed']:
                print(f"  - {test.test_id}: {test.name}")
                print(f"    Expected: {test.expected_result}, Got: {test.actual_result}")
        
        if error > 0:
            print(f"\n{Colors.ORANGE}Error Tests:{Colors.END}")
            for test in self.results['error']:
                print(f"  - {test.test_id}: {test.name}")
                print(f"    Error: {test.error}")
        
        print(f"\n{Colors.BOLD}{'='*60}{Colors.END}\n")
        
        # Save detailed results
        self.save_results()
    
    def save_results(self):
        """Save test results to JSON file"""
        results_data = {
            'timestamp': datetime.now().isoformat(),
            'total': len(self.test_cases),
            'passed': len(self.results['passed']),
            'failed': len(self.results['failed']),
            'errors': len(self.results['error']),
            'tests': []
        }
        
        for test in self.test_cases:
            results_data['tests'].append({
                'test_id': test.test_id,
                'name': test.name,
                'config_file': test.config_file,
                'expected_result': test.expected_result,
                'actual_result': test.actual_result,
                'passed': test.passed,
                'error': test.error
            })
        
        with open('test_results.json', 'w') as f:
            json.dump(results_data, f, indent=2)
        
        print(f"Detailed results saved to: test_results.json")

def main():
    runner = TestRunner()
    
    # Test Case 109: Allow vulnerable functions for LOW/MEDIUM
    runner.add_test(TestCase(
        test_id="TEST-109",
        name="GO - Allow vulnerable functions for LOW/MEDIUM severities",
        config_file="test_109_allow_vuln_func.yaml",
        expected_result="GO",
        expected_conditions=[],
        description="Vulnerable functions in LOW/MEDIUM should be allowed"
    ))
    
    # Test Case 402: max_allowed_severity = HIGH (should block HIGH)
    runner.add_test(TestCase(
        test_id="TEST-402",
        name="NO-GO - max_allowed_severity blocks HIGH vulnerabilities",
        config_file="test_402_max_severity_high.yaml",
        expected_result="NO-GO",
        expected_conditions=["CRITICAL or HIGH severity vulnerabilities"],
        description="HIGH severity should be blocked when max_allowed_severity = MEDIUM"
    ))
    
    # Test Case 404: max_new_vulnerabilities = 0
    runner.add_test(TestCase(
        test_id="TEST-404",
        name="NO-GO - max_new_vulnerabilities = 0 blocks new vulnerabilities",
        config_file="test_404_max_new_zero.yaml",
        expected_result="NO-GO",
        expected_conditions=["new vulnerabilities"],
        description="Should block promotion when new vulnerabilities are introduced"
    ))
    
    # Test Case 302: Severity exclusion for vulnerable_function
    runner.add_test(TestCase(
        test_id="TEST-302",
        name="Severity exclusion - skip vulnerable_function check",
        config_file="test_302_severity_exclusion.yaml",
        expected_result="GO",
        expected_conditions=[],
        description="Should skip vulnerable function check for excluded severities"
    ))
    
    # Test Case 202: Evaluate mode
    runner.add_test(TestCase(
        test_id="TEST-202",
        name="Evaluate mode - NO-GO on HIGH vulnerabilities",
        config_file="test_202_evaluate_mode.yaml",
        expected_result="NO-GO",
        expected_conditions=["CRITICAL or HIGH severity vulnerabilities"],
        description="Evaluate mode should assess certification environment standalone"
    ))
    
    # Run all tests
    runner.run_all_tests()
    
    # Exit with appropriate code
    if len(runner.results['failed']) > 0 or len(runner.results['error']) > 0:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
