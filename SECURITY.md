# Security Policy — RF Sentinel

## Intended Use

RF Sentinel is a **passive blue-team tool** (receive-only) intended for:

- Spectrum monitoring in authorised environments
- RF research and analysis in controlled lab settings
- Operation by organisations or individuals with appropriate licences or legal authority
- Security testing / auditing (red team) within a written, agreed-upon scope

**Strictly prohibited**: using this tool to interfere with, disrupt, or conduct unauthorised surveillance of any frequency or device.

---

## TX-Guard (Transmit Protection Layer)

RF Sentinel includes a **TX-Guard** — a hard safety mechanism designed to be non-disableable from user code.

### How It Works

1. **ReceiveOnlySDRProxy** — wraps every SDR object. Any attribute whose name relates to transmission (`transmit`, `tx_*`, `set_tx_*`, `start_tx`, etc.) is blocked with an `AttributeError`.

2. **verify_rx_guard_integrity()** — runs **before** the hardware connection is opened. It:
   - Verifies its own SHA-256 hash against a hardcoded value
   - Performs a self-test: attempts to call a TX method and confirms it actually raises
   - If either check fails → **the program aborts immediately** (exit code 2) with no fallback and no continuation

3. **TransmitBlockedError** — a dedicated exception type that cannot be confused with other errors.

### What TX-Guard Does Not Protect Against

TX-Guard is a software-level defence, not a physical one:

- If someone edits `SDR-BLUE-TEAM.py` directly and removes the proxy → the guard is bypassed
- Driver-level calls or `hackrf_transfer` invoked directly from a shell → outside scope
- Additional hardware with a separate TX module → outside scope

**The ultimate layer of protection is legal and physical, not software.**

---

## No Silent Failures Policy

RF Sentinel enforces the rule: **every error must be reported or re-raised**. Never `except: pass`.

This rule is automatically enforced by `check_no_swallow.py` in CI. See [CONTRIBUTING.md](CONTRIBUTING.md).

Security rationale: a silently swallowed error can cause:
- Anomaly baseline not being updated → prolonged false negatives
- TX-Guard not being initialised → no warning when the guard fails
- A degenerate model going undetected → the AI classifier issuing wrong verdicts

---

## Sensitive Data Protection

### Data Stored

- `rf_logs/rf_sentinel.db` — event log with power, entropy, threat type, timestamp
- `rf_logs/evidence/*.iq` + `.sigmf` — raw IQ snapshots of suspicious events
- `rf_logs/evidence/*.png` — spectrograms of IQ snapshots
- `rf_logs/fingerprints/*.json` — RF fingerprints per channel
- `rf_logs/reports/*.pdf` — incident reports from AutomatedResponseAgent

### Recommended Protections

```bash
# Restrict log directory permissions
chmod 700 rf_logs/
chown rf-sentinel:rf-sentinel rf_logs/ -R

# Encrypt evidence for long-term storage
# (IQ snapshots may contain sensitive signal content)
```

### Flask UI

The UI binds to `127.0.0.1:1717` (localhost only) by default. **Do not expose it to the internet** without authentication and TLS in front of it (e.g., an nginx reverse proxy).

For remote access:

```nginx
# nginx reverse proxy with Basic Auth
server {
    listen 443 ssl;
    location / {
        auth_basic "RF Sentinel";
        auth_basic_user_file /etc/nginx/.htpasswd;
        proxy_pass http://127.0.0.1:1717;
    }
}
```

---

## Webhook Security

Webhook URLs (Telegram / Discord / Slack) are passed via environment variables and must never be hardcoded:

```bash
export RF_WEBHOOK_TELEGRAM="https://api.telegram.org/bot<TOKEN>/sendMessage"
export RF_WEBHOOK_DISCORD="https://discord.com/api/webhooks/<ID>/<TOKEN>"
```

- Never commit `.env` files to version control
- Use `.gitignore` to exclude files containing tokens
- Rotate webhook tokens periodically

---

## Reporting a Vulnerability

### In Scope

- **TX-Guard bypass**: any method that causes the code to transmit without aborting
- **SQL injection** in `rf_logs/rf_sentinel.db`
- **Path traversal** in `save_evidence()` or the export API
- **Unauthenticated data modification** via the Flask API
- **Dependencies with a known CVE** in `requirements.txt`

Out of scope: HackRF hardware, the libhackrf driver, and vulnerabilities in third-party libraries (report those directly to their maintainers).

### Reporting Process

1. **Do not** open a public GitHub Issue for security vulnerabilities.
2. Send a description by email to: `security@[your-org].com`
   - Subject: `[RF-SENTINEL] Security Report`
   - Include: reproduction steps, impact assessment, and a PoC if available
3. You will receive a response within **72 hours**.
4. Once the fix is merged, we will credit you in the CHANGELOG (if you wish).

### Disclosure Policy

- **Responsible disclosure**: we ask for a minimum of 90 days to fix the issue before public disclosure.
- Do not attack third-party production systems to demonstrate a vulnerability.
- We will not pursue legal action against researchers acting in good faith under this policy.

---

## Routine Security Checks

```bash
# Check for no silent failures
python check_no_swallow.py

# Check TX-Guard integrity
python -c "
import importlib.util, sys
spec = importlib.util.spec_from_file_location('sdr', 'SDR-BLUE-TEAM.py')
# Do not exec — parse only to check syntax
print('TX-Guard: see verify_rx_guard_integrity() in source')
"

# Dependency audit
pip audit                          # requires: pip install pip-audit
safety check -r requirements.txt   # or: pip install safety
```

---

## Legal Compliance

Users are solely responsible for ensuring that their use of this tool complies with all applicable laws and regulations, including but not limited to:

- **Vietnam**: Radio Frequency Law 2009 (amended 2022), Decree 25/2011/ND-CP
- **EU**: Radio Equipment Directive (RED) 2014/53/EU
- **US**: FCC Part 15, Part 97 (Amateur Radio where applicable)
- The laws of the country or territory where the equipment is operated

> Using this tool implies that you have read, understood, and agreed to comply with all applicable legal requirements.
