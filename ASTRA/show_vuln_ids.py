#!/usr/bin/env python3
"""
Helper script to show vulnerability IDs for configuring exclusions.
Usage: python show_vuln_ids.py [pgi_id]
"""
import json
import sys
from pathlib import Path

def find_latest_report():
    """Find the most recent JSON report."""
    reports_dir = Path('reports')
    if not reports_dir.exists():
        print("Error: reports directory not found")
        return None
    
    json_files = list(reports_dir.glob('astra_report_*.json'))
    if not json_files:
        print("Error: No reports found")
        return None
    
    return max(json_files, key=lambda p: p.stat().st_mtime)

def show_vulnerabilities(pgi_id=None):
    """Show vulnerabilities for a specific PGI or all."""
    report_file = find_latest_report()
    if not report_file:
        return
    
    print(f"Reading: {report_file.name}\n")
    
    with open(report_file) as f:
        data = json.load(f)
    
    priorities = data.get('remediation_priorities', [])
    
    if pgi_id:
        # Show vulnerabilities for specific PGI
        print(f"Vulnerabilities affecting: {pgi_id}")
        print("="*100)
        count = 0
        for priority in priorities:
            for pgi in priority.get('affected_pgis', []):
                if pgi.get('id') == pgi_id:
                    count += 1
                    cve_list = priority.get('cveIds', [])
                    cve_str = ', '.join(cve_list) if cve_list else 'N/A'
                    print(f"\n{count}. {priority.get('title', 'N/A')[:70]}")
                    print(f"   CVE IDs:            {cve_str}")
                    print(f"   Severity:           {priority.get('severity', 'N/A')}")
                    print(f"   Davis Score:        {priority.get('davis_score', 'N/A')}")
                    print(f"   Impact:             {priority.get('impact', 0)}")
                    break
        
        if count == 0:
            print(f"\nNo vulnerabilities found for PGI: {pgi_id}")
        else:
            print(f"\n\nTotal: {count} vulnerabilities")
            print("\nTo exclude these, add to config.yaml under exclusions.pgis:")
            print(f"- pgi_id: \"{pgi_id}\"")
            print("  vulnerability_ids:")
            print("    - \"<External ID from above>\"")
    else:
        # Show all PGIs with vulnerability counts
        print("All entities with vulnerabilities:")
        print("="*100)
        
        pgi_map = {}
        for priority in priorities:
            for pgi in priority.get('affected_pgis', []):
                pgi_id = pgi.get('id')
                pgi_name = pgi.get('name', pgi_id)
                if pgi_id not in pgi_map:
                    pgi_map[pgi_id] = {'name': pgi_name, 'count': 0}
                pgi_map[pgi_id]['count'] += 1
        
        for idx, (pgi_id, info) in enumerate(sorted(pgi_map.items(), key=lambda x: x[1]['count'], reverse=True), 1):
            print(f"{idx}. {info['name']}")
            print(f"   PGI ID: {pgi_id}")
            print(f"   Vulnerability count: {info['count']}\n")
        
        print(f"\nRun with PGI ID to see detailed vulnerability list:")
        print(f"  python show_vuln_ids.py <PGI_ID>")

if __name__ == '__main__':
    pgi_id = sys.argv[1] if len(sys.argv) > 1 else None
    show_vulnerabilities(pgi_id)
