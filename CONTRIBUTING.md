# Contributing to RF Sentinel

Thank you for your interest in RF Sentinel! This guide will help you contribute effectively and consistently with the codebase.

---

## Before You Start

1. **Read [SECURITY.md](SECURITY.md)** — especially the TX-Guard and NO SILENT FAILURES sections.
2. **Run the test suite** to confirm your environment is working:
   ```bash
   python test_sdr_sentinel.py
   python check_no_swallow.py
   ```
3. **Open an issue** before starting a large feature — avoid finishing work only to find it won't be merged.

---

## Development Environment Setup

```bash
# Fork the repo on GitHub, then clone your fork
git clone https://github.com/<your-username>/rf-sentinel.git
cd rf-sentinel

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install all dependencies
pip install -r requirements.txt

# Pre-commit hook (recommended)
cp scripts/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Pre-commit hook contents:

```bash
#!/bin/bash
set -e
python check_no_swallow.py
python test_sdr_sentinel.py 2>&1 | tail -5
```

---

## Rule #1: NO SILENT FAILURES

This is the project's most important rule. **Every `except` block must:**

```python
# ✅ Correct — re-raise
try:
    something()
except ValueError:
    raise

# ✅ Correct — report clearly
try:
    something()
except ValueError as e:
    report_error("context_id", e)

# ✅ Correct — log at WARNING+ (acceptable when there is a good reason)
try:
    something()
except ValueError as e:
    logger.warning("falling back because %s", e)
    use_fallback()

# ✅ Correct — expected control flow with marker
try:
    item = q.get(timeout=1.0)
except queue.Empty:  # expected-exception: idle poll, queue empty most of the time
    continue
```

```python
# ❌ Wrong — silent swallow
try:
    something()
except ValueError:
    pass

# ❌ Wrong — fallback with no error report
try:
    x = parse(data)
except Exception:
    x = default_value   # no one knows the parse failed

# ❌ Wrong — debug level only
try:
    something()
except Exception as e:
    logger.debug("error: %s", e)   # invisible at the default INFO level

# ❌ Wrong — bare except
try:
    something()
except:                # catches KeyboardInterrupt and SystemExit too
    pass
```

`check_no_swallow.py` will reject PRs that contain violations. Run it before pushing:

```bash
python check_no_swallow.py
```

---

## Contribution Workflow

### 1. Create a branch

```bash
git checkout -b feat/feature-name     # new feature
git checkout -b fix/bug-description   # bug fix
git checkout -b docs/doc-name         # docs-only change
git checkout -b refactor/description  # refactor with no behaviour change
```

### 2. Write code

See [Code Style](#code-style) below.

### 3. Write / update tests

All logic changes require a corresponding test in `test_sdr_sentinel.py`.

No hardware? Use the existing mocks and fixtures:

```python
# Example — create an IQ fixture
def _make_iq(n=2048, noise_level=0.1):
    rng = np.random.default_rng(42)
    return (rng.standard_normal(n) + 1j * rng.standard_normal(n)) * noise_level
```

### 4. Run checks

```bash
python test_sdr_sentinel.py    # full test suite
python check_no_swallow.py     # no silent failures
```

### 5. Commit

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(agents): add multi-station bearing estimator
fix(rfclassifier): fix label leakage detection when <2 classes exist
docs(readme): update calibration guide
test(database): add edge-case tests for db_label_stats
refactor(sweep): extract wideband survey into its own function
```

### 6. Open a Pull Request

Use the template in [PULL_REQUEST_TEMPLATE.md](PULL_REQUEST_TEMPLATE.md). Fill it in completely, paying particular attention to **TX-Guard not affected** and **tests run**.

---

## Code Style

### Python

- **Python 3.8+** compatible — use `from __future__ import annotations` for type hints
- **PEP 8** with one exception: maximum line length is 100 characters (not 79)
- Type hints on all new function signatures
- Concise docstrings in English

```python
def analyze(channel: "Channel", r: dict, fp_store: dict) -> "ThreatResult":
    """
    Run the rule engine for one channel + raw_result.
    Returns a ThreatResult with threat_level, confidence, and anomaly_scores.
    """
    ...
```

### Naming Conventions

| Kind | Convention | Example |
|---|---|---|
| Module | `snake_case` | `rf_sentinel_agents.py` |
| Class | `PascalCase` | `RFThreatClassifier` |
| Function / method | `snake_case` | `detect_anomaly_ew()` |
| Constant | `UPPER_SNAKE_CASE` | `FHSS_HISTORY_LEN` |
| Private | `_prefix` | `_classify()`, `_ERR_STATE` |
| Expected exception marker | comment | `# expected-exception: reason` |

### report_error

`report_error(where, exc)` is the only function permitted to handle exceptions without re-raising. The `where` parameter must be a short, stable string used as a deduplication key:

```python
# ✅ Good — stable id
report_error("sweep.connect_hackrf", e, every=0)

# ❌ Avoid — changes with input, cannot be deduped
report_error(f"sweep.{channel.name}", e)
```

### JavaScript (Flask UI)

Every `catch` block in the dashboard HTML must call `reportUiError(...)` or `console.error(...)`:

```javascript
// ✅ Correct
fetch('/api/events')
  .then(r => r.json())
  .catch(e => { console.error('events load failed:', e); reportUiError(e); });

// ❌ Wrong — empty catch
fetch('/api/events').catch(() => {});
```

---

## Adding a New Threat Type

Checklist when adding a new threat type:

- [ ] Add the `Channel` to `WATCHLIST` in `SDR-BLUE-TEAM.py`
- [ ] Add the rule in `analyze()` for the new threat type
- [ ] Add a per-type model in `RFAnomalyAI.__init__()` if needed
- [ ] Add tests in `TestThreatRules`
- [ ] Update the threat types table in `README.md`
- [ ] Update `CHANGELOG.md`

---

## Adding a New Agent

New agents must:

1. Inherit from or conform to the interface of the existing agents in `rf_sentinel_agents.py`
2. Be registered in `AgentSuite.__init__()`
3. Not import `SDR-BLUE-TEAM` directly (use dependency injection)
4. Handle all exceptions with `report_error()` or re-raise
5. Have a test in `TestAgentsNoSilentFailure`

---

## What Must Not Be Changed

The following sections require special review and will generally not be accepted without a very strong justification:

| Section | Reason |
|---|---|
| `ReceiveOnlySDRProxy` | TX-Guard — changes may allow transmission |
| `verify_rx_guard_integrity()` | Contains a hardcoded hash of itself |
| `report_error()` | Must be byte-identical across all 3 files; tests verify this |
| `EXPECTED_TYPES` in `check_no_swallow.py` | Easy to abuse to bypass checks |

---

## Review Process

- Every PR requires at least 1 review from a maintainer
- PRs that affect TX-Guard or `check_no_swallow.py` require 2 reviews
- CI must pass (tests + check_no_swallow)
- Squash-merge into `main`

Thank you for contributing! 🎯
