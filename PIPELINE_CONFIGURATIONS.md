# Optimal Pipeline Configurations

Based on Groq's **30 requests/minute limit**, here are the recommended sustainable pipeline configurations.

## Configuration Presets

### Preset 1: Ultra-Conservative (Guaranteed Stability)
**Best for:** Getting reliable LLM analysis with zero errors
```bash
# 30 logs at 5-second intervals = 2.5 minutes,  12 logs/min (60% safety margin)
python generate_jitter_stream.py --rows 30 --interval_sec 5.0

# OR use the launcher:
powershell .\run_lean_test.ps1 -Rows 30 -IntervalSec 5.0
```
- **Total duration:** ~2.5 minutes
- **LLM calls:** 12/minute (60% safety margin below 30/min limit)
- **Throttling:** ZERO
- **Result:** Every log gets clean LLM analysis

---

### Preset 2: Moderate Throughput
**Best for:** Balancing analysis quality with faster feedback
```bash
# 60 logs at 2.5-second intervals = 2.5 minutes, 24 logs/min (20% safety margin)
python generate_jitter_stream.py --rows 60 --interval_sec 2.5

# OR:
powershell .\run_lean_test.ps1 -Rows 60 -IntervalSec 2.5
```
- **Total duration:** ~2.5 minutes
- **LLM calls:** 24/minute (20% safety margin below 30/min limit)
- **Throttling:** Minimal
- **Result:** Most logs get LLM analysis, some may be throttled

---

### Preset 3: Maximum Headroom
**Best for:** Days-long monitoring with absolute reliability
```bash
# 10 logs at 30-second intervals = 5 minutes, 2 logs/min (93% safety margin)
python generate_jitter_stream.py --rows 10 --interval_sec 30.0
```
- **Total duration:** ~5 minutes
- **LLM calls:** 2/minute (93% safety margin)
- **Throttling:** NONE
- **Result:** Every log manually analyzed

---

## Why These Configurations?

### The Math
- Groq limit: **30 requests/minute** = 1 request every 2 seconds
- Current LLM interval: **5.0 seconds** = 12 requests/minute max
- Formula: `logs_per_minute = (60 / interval_sec)`

### Throttling Explained
When logs arrive faster than the LLM can process them:
- **Fast incoming rate**: Many logs queue, LLM throttles some
- **Slow incoming rate**: Logs arrive at pace, LLM processes each cleanly

### Example: Why 30 @ 5sec works perfectly
```
Log 1 arrives at 0s   → LLM processes (completes by 5s)
Log 2 arrives at 5s   → LLM processes (completes by 10s)
Log 3 arrives at 10s  → LLM processes (completes by 15s)
...
No throttling, sequential clean analysis!
```

---

## Recommended Starting Point

**Start with: 30 logs at 5-second intervals**
```powershell
.\run_lean_test.ps1 -Rows 30 -IntervalSec 5.0
```

This gives you:
- ✓ Zero rate limit errors
- ✓ Zero throttling messages
- ✓ Clean, observable LLM analysis
- ✓ Perfect baseline for tuning

Once stable, you can increase throughput by reducing `IntervalSec` or adding more logs.

---

## Customizing for Your Needs

Adjust based on your goals:

| Goal | Configuration | Benefit |
|------|---------------|---------|
| Maximum reliability | `--rows 10 --interval_sec 30.0` | 2 logs/min (93% safety) |
| Quality first | `--rows 30 --interval_sec 5.0` | 12 logs/min (60% safety) |
| Balanced | `--rows 60 --interval_sec 2.5` | 24 logs/min (20% safety) |
| High throughput | `--rows 120 --interval_sec 1.0` | 60 logs/min (2x over limit!) ⚠️ DON'T USE |

---

## Monitoring Your Pipeline

Check logs for these signals:

```
✓ GOOD: "LLM throttled to protect token budget (4.8s wait)" - means safe margin
✗ BAD:  "LLM skipped due to cooldown" - too fast, increase interval_sec
✗ BAD:  "rate_limit_exceeded" or "429" - way too fast, decrease interval_sec
```
