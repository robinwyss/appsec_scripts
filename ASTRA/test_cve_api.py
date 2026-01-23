#!/usr/bin/env python3
"""Test script to check CVE data from API"""
import sys
sys.path.insert(0, '..')
from dynatrace_api import DynatraceApi
import yaml
import json

# Load config
with open('config.yaml') as f:
    config = yaml.safe_load(f)

# Initialize API
api = DynatraceApi(
    config['dynatrace']['environment'],
    config['dynatrace']['api_token'],
    True
)

# Get security problems
print("Fetching security problems...")
problems = api.getThirdPartySecurityProblems()
print(f"Found {len(problems)} problems\n")

if problems:
    first_problem = problems[0]
    print('='*80)
    print('Basic security problem fields (from list):')
    print('='*80)
    for key in sorted(first_problem.keys()):
        print(f"  {key}: {first_problem.get(key)}")
    
    print('\n' + '='*80)
    print(f'Fetching details for: {first_problem["securityProblemId"]}')
    print('='*80)
    details = api.getSecurityProblemDetails(first_problem['securityProblemId'])
    
    print('\nDetailed security problem fields:')
    for key in sorted(details.keys()):
        value = details.get(key)
        if isinstance(value, (dict, list)) and len(str(value)) > 100:
            print(f"  {key}: <{type(value).__name__} with {len(value)} items>")
        else:
            print(f"  {key}: {value}")
    
    print(f'\n{"="*80}')
    print(f'Has cveIds? {" cveIds" in details}')
    if 'cveIds' in details:
        print(f'CVE IDs: {details["cveIds"]}')
    else:
        print('CVE IDs field NOT FOUND')
        print('\nAll keys:', list(details.keys()))
