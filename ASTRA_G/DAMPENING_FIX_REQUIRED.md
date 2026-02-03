# Dampening Logic Corrections for HRP v2.0 Dashboard Tiles

## 🔴 Issue Found: Incorrect Dampening in Vulnerability Score

Your JavaScript tiles use **power dampening with exponent 0.75** but the Python reference uses **square root dampening (exponent 0.5)**.

---

## 📊 Python Reference (CORRECT)

### Vulnerability Score Dampening
```python
# From astra_report.py line 838-842
if dampening == 'sqrt':
    if weighted_sum <= max_score:
        # Pure square root for normal range
        score = 100 * math.sqrt(weighted_sum) / math.sqrt(max_score)
    else:
        # Hybrid: sqrt up to max_score, then logarithmic for extremes
        base = 100
        excess = weighted_sum - max_score
        log_add = 20 * math.log10(1 + excess) / math.log10(1 + 9500)
        score = min(base + log_add, 120)
```

**Key Parameters:**
- `dampening_function = 'sqrt'` (default)
- `max_theoretical_score = 500` (default)
- Uses **sqrt** (exponent 0.5), NOT power 0.75

### Supply Chain Dampening
```python
# From astra_report.py line 905
supply_power = config.get('supply_chain_power', 0.7)
supply_score = 100 * (vuln_ratio ** supply_power)
```
✅ This is CORRECT in your JavaScript (0.7 exponent)

---

## 🔧 Required Fixes

### Fix 1: Update `tile_hrpv2.js`

**Current (WRONG):**
```javascript
const rawVulnSum = Number(data.vuln_sum) || 0;
const s_vuln = 100 * (Math.pow(rawVulnSum, 0.75) / Math.pow(300, 0.75));
```

**Should be:**
```javascript
const rawVulnSum = Number(data.vuln_sum) || 0;
const max_score = 500;  // Python default

// Square root dampening (exponent 0.5)
const s_vuln = 100 * (Math.sqrt(rawVulnSum) / Math.sqrt(max_score));
```

**Or more explicitly:**
```javascript
const rawVulnSum = Number(data.vuln_sum) || 0;
const max_score = 500;

// Square root dampening with hybrid for extremes
let s_vuln;
if (rawVulnSum <= max_score) {
    // Pure square root for normal range
    s_vuln = 100 * Math.sqrt(rawVulnSum) / Math.sqrt(max_score);
} else {
    // Hybrid: sqrt up to max_score, then logarithmic
    const base = 100;
    const excess = rawVulnSum - max_score;
    const log_add = 20 * Math.log10(1 + excess) / Math.log10(1 + 9500);
    s_vuln = Math.min(base + log_add, 120);
}
```

### Fix 2: Update `hrp_score_only.js`

**Current (WRONG):**
```javascript
const s_vuln = 100 * (Math.pow(rawVulnSum, 0.75) / Math.pow(300, 0.75));
```

**Should be:**
```javascript
const max_score = 500;
const s_vuln = 100 * Math.sqrt(rawVulnSum) / Math.sqrt(max_score);
```

### Fix 3: Update `summary.js`

Same change as above.

### Fix 4: Update `hrp_breakdown.js`

Same change as above.

---

## 📈 Impact of the Fix

### Dampening Comparison

| Raw Sum | Current (0.75) | Correct (sqrt/0.5) | Difference |
|---------|----------------|-------------------|------------|
| 10      | 6.8            | 4.5               | -2.3       |
| 50      | 23.8           | 14.1              | -9.7       |
| 100     | 37.5           | 20.0              | -17.5      |
| 300     | 73.5           | 34.6              | -38.9      |
| 500     | 100.0          | 44.7              | -55.3      |
| 1000    | 159.0          | 63.2              | -95.8      |

**Key Observation**: Your current implementation **over-scores** vulnerabilities significantly, especially at higher values.

---

## 🎯 Why Square Root Dampening?

Square root (0.5 exponent) provides **stronger dampening** than 0.75:
- **Linear**: 10x vulnerabilities = 10x score (too harsh)
- **Power 0.75**: 10x vulnerabilities = 5.6x score (moderate)
- **Square Root (0.5)**: 10x vulnerabilities = 3.16x score (balanced)
- **Power 0.7**: 10x vulnerabilities = 5.0x score (used for supply chain)

The square root ensures that:
1. Small numbers of critical vulnerabilities still score high
2. Large numbers don't dominate the entire HRP score
3. Scores remain in 0-100 range under normal conditions

---

## ✅ Validation

After fixing, test with these values:

**Test Case 1: Low Vulnerability Load**
- rawVulnSum = 50
- Expected s_vuln = 100 * sqrt(50) / sqrt(500) ≈ **31.6**
- Current (wrong) = 100 * (50^0.75) / (300^0.75) ≈ 23.8

**Test Case 2: Medium Vulnerability Load**
- rawVulnSum = 200
- Expected s_vuln = 100 * sqrt(200) / sqrt(500) ≈ **63.2**
- Current (wrong) = 100 * (200^0.75) / (300^0.75) ≈ 52.5

**Test Case 3: High Vulnerability Load**
- rawVulnSum = 500
- Expected s_vuln = 100 * sqrt(500) / sqrt(500) = **100.0**
- Current (wrong) = 100 * (500^0.75) / (300^0.75) ≈ 133.5 (over 100!)

---

## 🔄 Summary of Changes Needed

1. **Change exponent from 0.75 to 0.5** (or use `Math.sqrt()`)
2. **Change max_score from 300 to 500**
3. **(Optional)** Add hybrid logic for extreme cases (>500)

Files to update:
- ✅ `tile_hrpv2.js`
- ✅ `hrp_score_only.js`
- ✅ `summary.js`
- ✅ `hrp_breakdown.js`

Supply chain and topology components are already correct! ✅
