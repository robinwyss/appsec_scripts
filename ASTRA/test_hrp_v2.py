#!/usr/bin/env python3
"""Test HRP v2.0 implementation with baseline and what-if scenarios."""

import json
import sys
from pathlib import Path

# Expected results based on HRP_V2_PROPOSAL.md
EXPECTED_BASELINE = {
    "vulnerabilities": 70,
    "score": 63.72,
    "rating": "HIGH"
}

EXPECTED_WHATIF = {
    "vulnerabilities": 59,
    "score": 58.66,
    "rating": "MEDIUM",
    "excluded": 11
}

def load_report(filepath):
    """Load and parse ASTRA JSON report."""
    with open(filepath, 'r') as f:
        return json.load(f)

def analyze_hrp_v2_report(report):
    """Extract HRP v2 metrics from report."""
    overall_risk = report.get('overall_risk', {})
    
    return {
        'score': overall_risk.get('score'),
        'rating': overall_risk.get('rating'),
        'model': overall_risk.get('model'),
        'vulnerability_count': report.get('vulnerability_summary', {}).get('total', 0),
        'exclusion_count': report.get('exclusion_summary', {}).get('excluded_count', 0),
        'components': overall_risk.get('components', {})
    }

def main():
    print("=" * 80)
    print("HRP v2.0 Implementation Test")
    print("=" * 80)
    print()
    
    # Find latest report files
    reports_dir = Path('reports')
    if not reports_dir.exists():
        print("❌ Reports directory not found. Please run ASTRA first.")
        return 1
    
    # Get the two most recent reports
    report_files = sorted(reports_dir.glob('astra_report_*.json'), reverse=True)
    
    if len(report_files) < 1:
        print("❌ No report files found. Please run ASTRA first.")
        return 1
    
    print(f"📊 Analyzing most recent report: {report_files[0].name}")
    print()
    
    # Analyze latest report
    latest_report = load_report(report_files[0])
    metrics = analyze_hrp_v2_report(latest_report)
    
    print(f"Model: {metrics['model']}")
    print(f"Vulnerability Count: {metrics['vulnerability_count']}")
    print(f"Excluded Count: {metrics['exclusion_count']}")
    print(f"HRP Score: {metrics['score']}")
    print(f"Risk Rating: {metrics['rating']}")
    print()
    
    if metrics.get('components'):
        print("Component Scores:")
        for component, value in metrics['components'].items():
            print(f"  - {component}: {value}")
        print()
    
    # Validate against expected values
    if metrics['model'] == 'HRP2':
        print("✅ HRP v2.0 model detected!")
        print()
        
        # Determine if this is baseline or what-if
        is_whatif = metrics['exclusion_count'] > 0
        expected = EXPECTED_WHATIF if is_whatif else EXPECTED_BASELINE
        
        scenario_name = "What-if (with exclusions)" if is_whatif else "Baseline"
        print(f"📈 Scenario: {scenario_name}")
        print()
        
        # Compare with expected values
        print("Comparison with Expected Values:")
        print(f"  Vulnerabilities: {metrics['vulnerability_count']} (expected: {expected['vulnerabilities']})")
        
        score_diff = abs(metrics['score'] - expected['score'])
        score_match = "✅" if score_diff < 1.0 else "⚠️"
        print(f"  {score_match} Score: {metrics['score']} (expected: {expected['score']}, diff: {score_diff:.2f})")
        
        rating_match = "✅" if metrics['rating'] == expected['rating'] else "❌"
        print(f"  {rating_match} Rating: {metrics['rating']} (expected: {expected['rating']})")
        
        if is_whatif:
            print(f"  Excluded: {metrics['exclusion_count']} (expected: {expected['excluded']})")
        
        print()
        
        # Calculate sensitivity if we have both reports
        if len(report_files) >= 2:
            print("📊 Comparing with previous report...")
            prev_report = load_report(report_files[1])
            prev_metrics = analyze_hrp_v2_report(prev_report)
            
            if prev_metrics['model'] == 'HRP2':
                score_delta = metrics['score'] - prev_metrics['score']
                vuln_delta = metrics['vulnerability_count'] - prev_metrics['vulnerability_count']
                
                print(f"  Previous score: {prev_metrics['score']} [{prev_metrics['rating']}]")
                print(f"  Current score:  {metrics['score']} [{metrics['rating']}]")
                print(f"  Score change:   {score_delta:+.2f} points")
                print(f"  Vulnerability change: {vuln_delta:+d} vulnerabilities")
                
                if vuln_delta != 0:
                    sensitivity = score_delta / vuln_delta
                    print(f"  Sensitivity:    {sensitivity:.2f} points per vulnerability")
                
                print()
                
                # Check if rating changed
                if prev_metrics['rating'] != metrics['rating']:
                    print(f"🎯 Rating Change: {prev_metrics['rating']} → {metrics['rating']}")
                    print()
    
    elif metrics['model'] == 'HRP':
        print("⚠️  HRP v1.0 detected. Set risk_model: 'HRP2' in config.yaml to use HRP v2.0")
        print()
    else:
        print(f"❓ Unknown model: {metrics['model']}")
        print()
    
    print("=" * 80)
    print("Test complete!")
    print("=" * 80)
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
