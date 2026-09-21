## Description

<!-- Briefly explain what this PR does and why. -->

## Type of Change

<!-- Check the relevant box -->

- [ ] 🐛 Bug fix (fixes a bug, no API change)
- [ ] ✨ New feature (adds functionality without breaking existing features)
- [ ] 💥 Breaking change (changes that break existing behaviour)
- [ ] 📚 Docs only (documentation changes only)
- [ ] ♻️ Refactor (improves code without changing behaviour)
- [ ] 🔐 Security fix
- [ ] ⚡ Performance

---

## Required Checklist

### 1. NO SILENT FAILURES

- [ ] `python check_no_swallow.py` passes with **0 violations**
  ```
  check_no_swallow: OK — X files, 0 swallowed errors.
  ```
- [ ] Every new `except` block has `report_error(...)`, `raise`, or logs at WARNING+
- [ ] No `except: pass` or `except E: return fallback` without reporting the error
- [ ] JavaScript `catch` blocks in the UI all call `console.error()` or `reportUiError()`

### 2. Tests

- [ ] `python test_sdr_sentinel.py` passes with **0 failures**
  ```
  Ran X tests in Y.Zs
  OK
  ```
- [ ] New tests added for changed logic (or explanation of why they are not needed)
- [ ] Tests do not require HackRF or any real hardware

### 3. TX-Guard

- [ ] This change does **NOT** affect `ReceiveOnlySDRProxy`
- [ ] This change does **NOT** affect `verify_rx_guard_integrity()`
- [ ] If it does affect either → explain why it is safe below ⬇️

### 4. report_error consistency

- [ ] If `report_error()` was changed → updated byte-identically in **all 3 files**:
  - `SDR-BLUE-TEAM.py`
  - `rf_sentinel_agents.py`
  - `rf_sentinel_ui.py`
- [ ] `TestReportError` still passes

### 5. Documentation

- [ ] `CHANGELOG.md` updated (under `[Unreleased]`)
- [ ] `README.md` updated if a feature was added or the API changed
- [ ] Docstrings / comments updated where necessary

---

## Technical Details

<!-- Explain your approach, design decisions, and trade-offs if any -->

## Screenshots / Output (if applicable)

<!-- Log output, UI screenshots, test results… -->

## TX-Guard Explanation (fill in if applicable)

<!-- If this PR touches ReceiveOnlySDRProxy or verify_rx_guard_integrity,
     explain in detail why the change is safe -->

## Breaking Changes (fill in if applicable)

<!-- List API / behaviour changes and provide migration guidance -->

---

## Related Issues

<!-- Closes #XXX -->
<!-- Fixes #XXX -->
<!-- Part of #XXX -->
