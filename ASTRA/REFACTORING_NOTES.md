# ASTRA Refactoring Notes
**Date**: January 22, 2026  
**Version**: v1.5.0

## Changes Made

### 1. Script Renamed
- **Old**: `astra_phase1.py`
- **New**: `astra_report.py`
- **Reason**: More generic name to support multiple phases

### 2. Phase Selection Architecture

#### Command-Line Interface
Added phase selection flags:
- `-1` or `--phase-1`: Run Phase 1 (current risk assessment)
- `-2` or `--phase-2`: Run Phase 2 (temporal comparison - not yet implemented)
- Default behavior: Phase 1 if no flag specified

#### Additional Arguments
- `--baseline`: Path to baseline JSON report for Phase 2 comparison
- `-c, --config`: Configuration file path (required)
- `--debug`: Enable debug logging

### 3. Code Structure Improvements

#### Modular Functions
- **`run_phase1(config)`**: Encapsulates all Phase 1 logic
  - Data collection
  - Risk calculation
  - Entity analysis
  - Report generation (JSON + PDF)
  
- **`run_phase2(config, baseline_report)`**: Placeholder for Phase 2
  - Currently raises `NotImplementedError`
  - Documents planned features
  
- **`main()`**: Entry point with argument parsing and phase routing

#### Benefits
1. **Separation of concerns**: Each phase is self-contained
2. **Easy testing**: Functions can be tested independently
3. **Future extensibility**: Phase 2 implementation won't require changes to Phase 1
4. **Clear error handling**: Different exit codes for different error types

### 4. Updated Configuration
- Log file renamed: `astra_phase1.log` → `astra_report.log`
- Module docstring updated to reflect multi-phase design

### 5. Documentation Updates

#### README.md
- Updated all script references from `astra_phase1.py` to `astra_report.py`
- Added phase selection examples
- Documented Phase 2 placeholder
- Updated configuration examples to include `risk_model` option

#### quickstart.sh
- Updated script name checks
- Added phase selection examples to output
- Simplified header (removed "Phase 1" specificity)

## Usage Examples

### Phase 1 (Default)
```bash
# All of these run Phase 1:
python3 astra_report.py -c config.yaml
python3 astra_report.py -c config.yaml --phase-1
python3 astra_report.py -c config.yaml -1
```

### Phase 2 (Future)
```bash
# Phase 2 with auto-selection of latest baseline:
python3 astra_report.py -c config.yaml --phase-2

# Phase 2 with specific baseline:
python3 astra_report.py -c config.yaml -2 --baseline reports/astra_report_20260122.json
```

### Debug Mode
```bash
python3 astra_report.py -c config.yaml --debug
```

## Exit Codes
- `0`: Success
- `1`: Runtime error (API failure, data collection error, etc.)
- `2`: Not implemented (Phase 2 functionality)

## Backward Compatibility

### Breaking Changes
- **Script name changed**: `astra_phase1.py` is now `astra_report.py`
  - The old file still exists but should be considered deprecated
  - All documentation and scripts updated to use new name

### Non-Breaking
- Configuration file format unchanged
- JSON/PDF output format unchanged
- All Phase 1 functionality preserved

## Phase 2 Planning

When implementing Phase 2, the following structure is already in place:

### Function Signature
```python
def run_phase2(config: AstraConfig, baseline_report: Optional[str] = None) -> None:
    """Execute Phase 2: Temporal comparison and trend analysis."""
```

### Planned Features (from placeholder)
- Comparison with previous JSON snapshots
- Risk trend analysis (improvement/degradation)
- Velocity calculations (risk change over time)
- Identification of new/resolved vulnerabilities
- Trend visualizations in PDF reports

### Implementation Guidelines
1. **Load baseline report**: Parse JSON from `baseline_report` path or auto-detect latest
2. **Run Phase 1**: Collect current data (can reuse `run_phase1` components)
3. **Compare data**: Calculate deltas between baseline and current
4. **Generate report**: Enhanced PDF with comparison metrics

## Testing Performed

✅ Help command displays correctly  
✅ Phase 1 executes with `-1` flag  
✅ Phase 1 executes with `--phase-1` flag  
✅ Phase 1 executes by default (no phase flag)  
✅ Phase 2 displays "not implemented" message  
✅ Exit codes correct (0 for success, 2 for not implemented)  
✅ Debug logging works  
✅ All existing functionality preserved  

## Future Enhancements

### Short Term
1. Implement Phase 2 temporal comparison
2. Add unit tests for phase selection logic
3. Create integration tests

### Medium Term
1. Phase 3: Predictive analysis (PARM model)
2. Multi-environment comparison
3. API endpoint for programmatic access

### Long Term
1. Web dashboard for trend visualization
2. Automated scheduling and alerting
3. Integration with ticketing systems

## Notes for Developers

### Adding New Phases
To add a new phase (e.g., Phase 3):

1. Create function:
   ```python
   def run_phase3(config: AstraConfig, **kwargs) -> None:
       """Execute Phase 3: Description."""
       # Implementation here
   ```

2. Add argument to parser:
   ```python
   phase_group.add_argument('-3', '--phase-3', dest='phase3', 
                           action='store_true',
                           help='Run Phase 3: Description')
   ```

3. Add routing in main():
   ```python
   elif args.phase3:
       run_phase3(config)
   ```

### Reusing Phase 1 Components
All Phase 1 classes are available for reuse:
- `DataCollector`: For data gathering
- `RiskCalculator`: For risk scoring
- `JsonExporter`: For JSON report generation
- `PdfGenerator`: For PDF report generation

Example:
```python
def run_phase2(config: AstraConfig, baseline_report: Optional[str] = None) -> None:
    # Reuse Phase 1 data collection
    api = DynatraceApi(...)
    collector = DataCollector(api, config)
    current_data = collector.collect_all_data()
    
    # Load baseline
    with open(baseline_report) as f:
        baseline_data = json.load(f)
    
    # Calculate comparison
    comparison = compare_assessments(baseline_data, current_data)
    
    # Generate report
    # ...
```

## Version History

- **v1.5.0** (Jan 22, 2026): Refactored to multi-phase architecture
  - Script renamed to `astra_report.py`
  - Added phase selection flags
  - Modularized Phase 1 logic
  - Added Phase 2 placeholder
  - Updated all documentation

- **v1.4.0** (Jan 22, 2026): Bug fixes
  - Fixed entity mapping (0→28 entities)
  - Fixed risk_model metadata bug
  - Changed from CVSS to Davis Security Score

- **v1.3.0** (Jan 22, 2026): Enhanced PDF with analysis + methodology pages
- **v1.2.0** (Jan 22, 2026): Added REI model support
- **v1.1.0** (Jan 22, 2026): Added parallelization (10 workers)
- **v1.0.0** (Jan 22, 2026): Initial CWRS implementation

---

*This document serves as a reference for the v1.5.0 refactoring. Update this file when making significant architectural changes.*
