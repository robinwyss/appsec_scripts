# HRP v2.0 Auto-Dampening Optimization

## Overview

The auto-dampening optimization feature automatically adjusts HRP v2.0 dampening parameters based on your environment's vulnerability profile. It uses grid search to find optimal parameters that:

1. **Place scores in actionable range** (70-90, optimal ~80)
2. **Maintain visible sensitivity** (8-15 point reduction for top 5 fixes)
3. **Avoid saturation** (no components at 95%+)
4. **Match environment complexity** (vulnerability count and severity)

## Why Optimize Dampening?

HRP v2.0 uses dampening to prevent score saturation when vulnerability counts are high. However, the optimal parameters vary by environment:

- **High vulnerability environments** (100+): Need stronger dampening (lower exponent, higher max score)
- **Low vulnerability environments** (<20): Need less dampening (higher exponent, lower max score)
- **Saturated scores** (components at 100): Indicate insufficient dampening

Manual tuning is time-consuming and requires expertise. Auto-optimization does this automatically.

## Usage

### Basic Usage

Run an assessment with automatic optimization:

```bash
python astra_report.py -c config.yaml --hrp-dampen
```

This will:
1. Complete a normal assessment
2. Analyze your environment's vulnerability profile
3. Test 25 parameter combinations (5 exponents × 5 max scores)
4. Display recommendations with rationale
5. Prompt you to apply changes

### Workflow

```
┌─────────────────────────┐
│  Run Assessment         │
└───────────┬─────────────┘
            │
            v
┌─────────────────────────┐
│  Analyze Environment    │
│  - Vulnerability count  │
│  - Severity distribution│
│  - Current saturation   │
└───────────┬─────────────┘
            │
            v
┌─────────────────────────┐
│  Grid Search (25 tests) │
│  - Exponents: 0.55-0.75 │
│  - Max scores: 300-800  │
└───────────┬─────────────┘
            │
            v
┌─────────────────────────┐
│  Evaluate Fitness       │
│  - Score placement      │
│  - Fix sensitivity      │
│  - Saturation check     │
└───────────┬─────────────┘
            │
            v
┌─────────────────────────┐
│  Display Recommendations│
│  + Rationale            │
└───────────┬─────────────┘
            │
            v
┌─────────────────────────┐
│  User Confirmation      │
│  (yes/no)               │
└───────────┬─────────────┘
            │
            v
┌─────────────────────────┐
│  Backup + Update Config │
└─────────────────────────┘
```

## Example Output

```
================================================================================
HRP v2.0 - Auto-Dampening Optimization Results
================================================================================

Environment Analysis:
  • Total vulnerabilities: 96
  • Severity: 0 CRITICAL, 28 HIGH, 50 MEDIUM, 18 LOW
  • Current score: 78.42 [HIGH]
  • Saturated components: 2
    (vulnerability_risk, aging_penalty)

Parameter Comparison:
┌──────────────────────────────────────────────────────────────────────────────┐
│ Configuration                │ Current         │ Optimized       │ Change          │
├──────────────────────────────────────────────────────────────────────────────┤
│ Dampening Exponent           │ 0.75            │ 0.65            │ -0.10           │
│ Max Theoretical Score        │ 300             │ 500             │ +200            │
└──────────────────────────────────────────────────────────────────────────────┘

Projected Impact:
  • Current score:        71.23
  • After fixing top 5:   59.87
  • Score reduction:      -11.36 points
  • Saturated components: 0
  • Fitness score:        2.15 (lower is better)

Why These Parameters?
  • Balanced exponent (0.65) for 96 vulnerabilities
  • Moderate max score (500) balances range
  • Current score (71.2) in optimal actionable range
  • Good sensitivity: -11.4 points for top 5 fixes
  • Eliminates score saturation (headroom for worse scenarios)

Alternative Configurations (Top 5):
  1. Exp=0.65, Max=500: Score 71.23 → 59.87 (-11.36), Fitness=2.15
  2. Exp=0.60, Max=600: Score 68.45 → 55.12 (-13.33), Fitness=3.78
  3. Exp=0.70, Max=400: Score 74.56 → 63.21 (-11.35), Fitness=4.12
  4. Exp=0.65, Max=600: Score 70.89 → 58.34 (-12.55), Fitness=4.89
  5. Exp=0.60, Max=500: Score 69.12 → 56.78 (-12.34), Fitness=5.23

================================================================================

Apply these parameters? (yes/no):
```

## Configuration Changes

When you approve optimization, the tool:

1. **Backs up current config** to `config_backup_TIMESTAMP_before-optimization_expX.XX_maxXXX.yaml`
2. **Updates config.yaml** with new parameters:
   ```yaml
   hrp_v2:
     dampening_exponent: 0.65  # Was 0.75
     max_theoretical_score: 500  # Was 300
   ```

3. Preserves all other config settings and comments (uses ruamel.yaml)

## Understanding the Fitness Function

The optimizer scores each parameter combination using a fitness function (lower is better):

### 1. Score Placement (70-90 range, optimal 80)
- **Too low** (<70): Penalties reduce urgency and stakeholder buy-in
- **Too high** (>90): Less headroom for deterioration
- **Just right** (70-90): Actionable but with room to worsen

### 2. Fix Sensitivity (8-15 points, optimal 12)
- **Too low** (<8): Fixes barely move the needle, reduced motivation
- **Too high** (>15): Over-reactive, small changes cause large swings
- **Just right** (8-15): Clear improvement signal from fixes

### 3. Saturation Avoidance
- **20 points penalty** per component at 95%+
- Saturation means no headroom to show deterioration
- Critical for distinguishing between "bad" and "catastrophic"

## Parameter Search Space

The optimizer tests these combinations:

**Dampening Exponents:** 0.55, 0.60, 0.65, 0.70, 0.75
- Lower values = stronger dampening (for high vulnerability counts)
- Higher values = less dampening (for low vulnerability counts)

**Max Theoretical Scores:** 300, 400, 500, 600, 800
- Lower values = scores run hotter (components reach 100 faster)
- Higher values = more headroom (components stay lower)

**Total combinations:** 5 × 5 = 25

## When to Optimize

Run optimization when:

- **Initial setup**: Finding the right parameters for your environment
- **Scores saturated**: Any component consistently at 95%+
- **No sensitivity**: Fixing vulnerabilities doesn't change scores
- **Major changes**: Significant increase/decrease in vulnerability count
- **Quarterly check**: Environment complexity can change over time

## Technical Details

### Implementation

The feature is implemented in `dampening_optimizer.py` with the following components:

**DampeningOptimizer Class:**
- `analyze_environment()`: Gathers environment metrics
- `identify_top_vulnerabilities()`: Finds highest-impact vulns for sensitivity test
- `simulate_with_params()`: Recalculates risk with different parameters
- `find_optimal_params()`: Grid search with fitness evaluation
- `backup_config()`: Saves current configuration
- `update_config()`: Applies optimized parameters
- `generate_report()`: Creates human-readable summary

### Grid Search Algorithm

```python
For each exponent in [0.55, 0.60, 0.65, 0.70, 0.75]:
    For each max_score in [300, 400, 500, 600, 800]:
        1. Calculate current score with these parameters
        2. Calculate score after fixing top 5 vulnerabilities
        3. Check for saturated components (95%+)
        4. Evaluate fitness (score placement + sensitivity + saturation)
        5. Track if best fitness so far
        
Return parameters with lowest (best) fitness score
```

### Sensitivity Testing

To measure fix sensitivity, the optimizer:
1. Identifies top 5 vulnerabilities by Davis score
2. Simulates removing them from the assessment
3. Recalculates risk score
4. Measures the reduction (current - fixed)

This tells you how much impact fixing high-priority vulns will have.

## Integration with ASTRA

The feature integrates seamlessly with existing ASTRA workflow:

**CLI Flag:** `--hrp-dampen` or `-hd`

**Requirements:**
- Must use HRP2 risk model in config.yaml
- Must run assessment first (provides data)

**Output:**
- Optimization report (console)
- Backup config file (for rollback)
- Updated config.yaml (if approved)

**No impact on:**
- Report generation (JSON/PDF)
- Other risk models (CWRS, REI, HRP_V1)
- Data collection or API calls

## Troubleshooting

### "Dampening optimization requires HRP2 model"
**Solution:** Update config.yaml:
```yaml
assessment:
  risk_model: 'HRP2'
```

### "Failed to load report data"
**Cause:** JSON report not found or corrupted
**Solution:** Ensure assessment completes successfully before optimization

### All parameters have high fitness scores
**Cause:** Unusual vulnerability profile (very high or very low counts)
**Solution:** Review top 5 alternatives, pick one closest to target range

### Optimization suggests extreme parameters (0.55 exp, 800 max)
**Interpretation:** Very high vulnerability count detected
**Action:** This is normal for environments with 150+ vulnerabilities

### No saturation but optimizer still recommends changes
**Reason:** Optimizing for sensitivity or score placement
**Decision:** If current scores work for you, changes are optional

## Best Practices

1. **Run optimization after first assessment**: Get baseline recommendations
2. **Review alternatives**: Top 5 configurations often have similar fitness
3. **Test before committing**: Run new assessment to verify improvements
4. **Keep backups**: Optimizer auto-backs up, but keep manual backups too
5. **Document changes**: Note optimization date and rationale in your records
6. **Rerun quarterly**: Environment complexity changes over time

## Advanced Usage

### Using Backup to Rollback

If optimized parameters don't work well:

```bash
# Find backup file
ls -l config_backup_*.yaml

# Restore backup
cp config_backup_20250123_143021_before-optimization_exp0.75_max300.yaml config.yaml

# Verify restoration
grep -A 5 "hrp_v2:" config.yaml
```

### Manual Parameter Tuning

If you want to manually test specific values:

```yaml
hrp_v2:
  dampening_exponent: 0.68  # Your custom value
  max_theoretical_score: 450  # Your custom value
```

Then run assessment:
```bash
python astra_report.py -c config.yaml --phase-1
```

### Comparing Multiple Configurations

To test multiple parameter sets:

1. Backup current config: `cp config.yaml config_original.yaml`
2. Update parameters in config.yaml
3. Run assessment: `python astra_report.py -c config.yaml -1`
4. Note the scores
5. Repeat steps 2-4 with different parameters
6. Compare results and choose best

## Dependencies

The optimization feature requires:
- `ruamel.yaml` (preferred, preserves formatting)
- Falls back to `PyYAML` if ruamel.yaml unavailable

Install:
```bash
pip install ruamel.yaml
```

## Performance

- **Grid search**: 25 parameter combinations
- **Time**: ~5-10 seconds (depends on entity count)
- **No API calls**: Uses existing report data
- **No file I/O during search**: All in-memory calculations

## Future Enhancements

Potential improvements for future versions:

1. **Bayesian optimization**: Smarter search than grid
2. **Multi-objective optimization**: Balance multiple fitness criteria
3. **Historical tracking**: Learn from past optimizations
4. **Confidence intervals**: Uncertainty quantification
5. **What-if scenarios**: Test custom vulnerability profiles
6. **Batch optimization**: Optimize multiple configs at once

## Support

For issues or questions:
1. Check this documentation
2. Review DEVELOPMENT_HISTORY.md for implementation details
3. Run with `--debug` flag for detailed logging
4. Examine generated backup files for before/after comparison
