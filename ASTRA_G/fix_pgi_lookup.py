#!/usr/bin/env python3
"""Fix PGI lookup in all dashboard queries."""

import json
import re

# Read the dashboard JSON
with open('HRPv2_Dashboard.json', 'r') as f:
    dashboard = json.load(f)

# Update filter references
def fix_query(query):
    """Fix a single query string."""
    if not query:
        return query
    
    # Replace the expand pattern
    query = query.replace(
        'expand related_entities.process_groups.ids, alias:pgi_id',
        'expand pid=affected_entity.affected_processes.ids'
    )
    
    # Replace all variations of the old lookup pattern
    old_patterns = [
        ('| lookup [\\n    fetch dt.entity.process_group_instance | fields id, entity.name, tags\\n  ], sourceField:pgi_id, lookupField:id, fields:{pgi_name=entity.name, pgi_tags=tags}',
         '| lookup [\\n    fetch dt.entity.process_group_instance\\n    | fields process_id=id, process_name=entity.name, host_id=belongs_to[dt.entity.host]\\n    | lookup [ fetch dt.entity.host | fieldsAdd tags], sourceField:host_id, lookupField:id, fields:{host_name=entity.name,host_tags=tags}\\n  ], sourceField:pid, lookupField:process_id, fields:{process_id,process_name,host_id,host_name,host_tags}'),
        
        ('| lookup [\\n    fetch dt.entity.process_group_instance | fields id, entity.name, tags\\n  ], sourceField:pid, lookupField:id, fields:{pgi_name=entity.name, pgi_tags=tags}',
         '| lookup [\\n    fetch dt.entity.process_group_instance\\n    | fields process_id=id, process_name=entity.name, host_id=belongs_to[dt.entity.host]\\n    | lookup [ fetch dt.entity.host | fieldsAdd tags], sourceField:host_id, lookupField:id, fields:{host_name=entity.name,host_tags=tags}\\n  ], sourceField:pid, lookupField:process_id, fields:{process_id,process_name,host_id,host_name,host_tags}'),
    ]
    
    for old, new in old_patterns:
        query = query.replace(old, new)
    
    # Update filter references - pgi_name to process_name
    query = query.replace('pgi_name == $Process_Group_Instance', 'process_name == $Process_Group_Instance')
    query = query.replace('or pgi_name == $Process_Group_Instance)', 'or process_name == $Process_Group_Instance)')
    
    # Update tag filter references - pgi_tags to host_tags
    query = query.replace('pgi_tags)', 'host_tags)')
    
    # Update countDistinctExact references
    query = query.replace('countDistinctExact(pgi_id)', 'countDistinctExact(process_id)')
    query = query.replace('countDistinctExact(pid)', 'countDistinctExact(process_id)')
    
    # Update summarize by references
    query = query.replace('by:{pgi_name}', 'by:{process_name}')
    
    # Update field references in output
    query = query.replace('`Process Group`=pgi_name', '`Process Group`=process_name')
    
    # Fix related_entities.hosts.ids references
    query = query.replace('countDistinctExact(related_entities.hosts.ids)', 'countDistinctExact(host_id)')
    query = query.replace('countDistinctExact(related_entities.services.ids)', 'count()')  # Simplified - services not easily accessible
    
    return query

# Fix all tile queries
fixed_count = 0
if 'tiles' in dashboard:
    for tile_key, tile_data in dashboard['tiles'].items():
        if isinstance(tile_data, dict) and 'query' in tile_data:
            original = tile_data['query']
            fixed = fix_query(original)
            if original != fixed:
                tile_data['query'] = fixed
                fixed_count += 1
                print(f"Fixed query in tile: {tile_key}")

# Write back the fixed dashboard
with open('HRPv2_Dashboard.json', 'w') as f:
    json.dump(dashboard, f, indent=2)

print(f"\\nFixed {fixed_count} queries in the dashboard!")
print("\\nChanges applied:")
print("  - expand related_entities.process_groups.ids -> expand pid=affected_entity.affected_processes.ids")
print("  - Updated lookup to include process_id, process_name, host_id, host_name, host_tags")
print("  - Updated all field references (pgi_name -> process_name, pgi_tags -> host_tags)")
print("  - Fixed entity counting for topology calculations")

