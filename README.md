# RF Sentinel v2 — Dual-AI RF Monitor (Blue Team)

> **A passive (receive-only) radio-frequency spectrum monitor that detects anomalies and classifies threats using a multi-layer AI pipeline.**

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: BSD-3-Clause](https://img.shields.io/badge/License-BSD%203--Clause-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-unittest-brightgreen)](test_sdr_sentinel.py)
[![No Silent Failures](https://img.shields.io/badge/errors-no%20silent%20failures-red)](check_no_swallow.py)

---

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Hardware & Software Requirements](#requirements)
4. [Installation](#installation)
5. [Configuration & Calibration](#configuration--calibration)
6. [Usage](#usage)
7. [Monitored Threat Types](#monitored-threat-types)
8. [Web UI](#web-ui)
9. [Agent Layer](#agent-layer)
10. [Architecture](#architecture)
11. [Testing](#testing)
12. [CI — check_no_swallow](#ci--check_no_swallow)
13. [Warnings & Limitations](#warnings--limitations)
14. [Directory Structure](#directory-structure)
15. [Changelog](#changelog)
16. [License](#license)

---

## Introduction

RF Sentinel is a **radio-frequency spectrum monitoring** tool for **blue team** (defensive) use. It connects to a **HackRF One** (or equivalent SDR), performs continuous sweeps across a configurable channel watchlist, and detects anomalous behaviour using a three-layer AI pipeline.

**Fully passive** — the tool only receives signals (RX) and never transmits. A hard TX-Guard layer immediately aborts the program if any TX call bypasses the receive-only proxy.

The system is written in pure Python with no special drivers beyond `pyhackrf` / `pyrtlsdr`, and runs reliably on Linux, macOS, and WSL2.

---

## Features

| Group | Detail |
|---|---|
| **AI / ML** | Dual-AI: DBSCAN + IsolationForest (global) · HMM / LOF / OCSVM / IF (per-type) · RandomForest / LightGBM / XGBoost (supervised) |
| **DSP** | Savitzky-Golay spectrum pre-filter · DTW FHSS pattern tracker · CAF cyclostationary analysis · FFT / PSD / kurtosis / sample entropy / STFT entropy |
| **Confidence gating** | 4 layers: Persistence · Critical Z-score · EMA drift · RF downgrade-only |
| **Wideband survey** | 300–1000 MHz scan to discover channels outside the watchlist |
| **Agent plugins** | SOM · Teacher-Student · Cognitive Freq · Active Learning · Automated Response · Protocol Decoder |
| **Web UI** | Flask :1717 · Chart.js donut/line/bar · SSE real-time · CSV/JSON export · Calibration wizard |
| **Database** | SQLite with schema versioning · auto-label pipeline · spectrum history |
| **Safety** | ReceiveOnlySDRProxy TX-guard · SHA-256 hash integrity check · NO SILENT FAILURES policy |
| **Testing** | 20+ test classes, zero hardware required |

---

## Requirements

### Hardware

- **HackRF One** (https://greatscottgadgets.com/hackrf/) — required for normal mode
- USB 2.0 or better
- HackRF does not need a calibrated LNA/PA to run, but a **calibration pass** is required for accurate dBm readings (see [Configuration & Calibration](#configuration--calibration))

> **No HackRF?** Run `--web-only` to start the UI and DB without hardware. Useful for replaying saved events or debugging routes.

### Software (Python 3.8+)

```
Python >= 3.8
numpy >= 1.21
scipy >= 1.7
scikit-learn >= 1.0
joblib >= 1.1
flask >= 2.0
pyhackrf >= 0.1.0    # or pyrtlsdr for RTL-SDR
```

Full dependency list: [requirements.txt](requirements.txt).

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/your-org/rf-sentinel.git
cd rf-sentinel
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

Optional deps (LightGBM, XGBoost, PDF reports, etc.) are in the same file under the `[OPTIONAL]` section. Uncomment or install individually as needed.

### 4. Install HackRF driver (Linux)

```bash
# Ubuntu / Debian
sudo apt install hackrf libhackrf-dev
# Verify connection
hackrf_info
```

### 5. Grant USB permissions (Linux — avoid sudo)

```bash
sudo cp udev/53-hackrf.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
# Replug HackRF
```

### 6. Verify the installation

```bash
python test_sdr_sentinel.py      # full test suite, no hardware required
python check_no_swallow.py       # verify no silently-swallowed errors
```

---

## Configuration & Calibration

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `RF_SENTINEL_LOGS_DIR` | `./rf_logs/` | Directory for DB, logs, and evidence |
| `RF_WEBHOOK_TELEGRAM` | — | Telegram webhook URL for alerts |
| `RF_WEBHOOK_DISCORD` | — | Discord webhook URL |
| `RF_WEBHOOK_SLACK` | — | Slack webhook URL |
| `RF_RESPONSE_SCRIPT` | — | Shell script to run on HIGH/CRITICAL alert |

Example `.env`:

```bash
export RF_SENTINEL_LOGS_DIR=/var/lib/rf-sentinel/logs
export RF_WEBHOOK_TELEGRAM=https://api.telegram.org/bot<TOKEN>/sendMessage
```

### Power calibration (required for accurate dBm readings)

> **Important**: Without calibration, dBm values are relative only (default offset `-50.0 dB`). The system still detects anomalies via Z-score (relative), but absolute dBm thresholds will be wrong.

Each frequency band has an `offset_dB`:

```
offset_dB = true_power_dBm − sdr_reading_dBm
```

**Calibration procedure (signal generator)**

| Band | Recommended test frequency |
|---|---|
| 100–200 MHz | 150 MHz |
| 200–400 MHz | 300 MHz |
| 400–700 MHz | 500 MHz |
| 700–1000 MHz | 868 MHz |
| 1000–1500 MHz | 1090 MHz |
| 1500–2400 MHz | 1575 MHz |
| 2400–3000 MHz | 2437 MHz |
| 3000–6000 MHz | 5800 MHz |

For each band:
1. Set signal generator to the test frequency at a known output level `P_gen_dBm`.
2. Connect to HackRF via cable + appropriate attenuator.
3. Open **Channel monitor** in the UI and select a channel in that band.
4. Record `P_sdr_dBm` from the UI.
5. Compute `offset = P_gen_dBm - P_sdr_dBm`.

Enter offsets via **UI → Calibration → Save**, or via the API:

```bash
curl -X POST http://127.0.0.1:1717/api/calibration \
  -H "Content-Type: application/json" \
  -d '{
    "bands": [
      [100e6, 200e6, -3.5],
      [200e6, 400e6, -4.1],
      [400e6, 700e6, -5.0],
      [700e6, 1000e6, -5.8],
      [1000e6, 1500e6, -6.2],
      [1500e6, 2400e6, -7.0],
      [2400e6, 3000e6, -8.5],
      [3000e6, 6000e6, -12.0]
    ]
  }'
```

After saving, the UI shows `✅ CALIBRATION_VERIFIED`.

**Typical offset reference (HackRF One)**

| Band | Typical offset |
|---|---|
| 100–400 MHz | −2 to −5 dB |
| 400–1000 MHz | −4 to −7 dB |
| 1000–2400 MHz | −6 to −10 dB |
| 2400–6000 MHz | −8 to −15 dB |

Larger offsets at higher frequencies are normal due to cable loss and the internal LNA frequency response.

**Recalibration schedule**

| Situation | Action |
|---|---|
| HackRF or antenna replaced | Full recalibration |
| Ambient temperature change > 15°C | Recalibrate |
| After 6 months of operation | Recheck 2–3 primary bands |
| Sudden drop in RF model accuracy | Check calibration before retraining |

---

## Usage

### Normal mode (HackRF required)

```bash
python SDR-BLUE-TEAM.py
```

The system will:
1. Initialise the SQLite DB and Random Forest.
2. Start the Flask UI at `http://127.0.0.1:1717/`.
3. Connect to HackRF.
4. Run an 8-round baseline sweep.
5. Enter the continuous monitoring loop (Ctrl+C to stop).

### Web-only mode (no hardware)

```bash
python SDR-BLUE-TEAM.py --web-only
```

Starts Flask + DB without opening HackRF. Useful for replaying saved events, debugging routes, or testing the UI.

### Force model retrain

```bash
python SDR-BLUE-TEAM.py --train-now
# Combinable with --web-only:
python SDR-BLUE-TEAM.py --web-only --train-now
```

---

## Monitored Threat Types

| Threat type | Channel | Band | Description |
|---|---|---|---|
| `GPS_JAM` | GPS L1, L2 | 1575 / 1227 MHz | Deliberate GPS jamming |
| `FAKE_BTS` | GSM900, GSM1800 | 935 / 1842 MHz | Fake BTS / IMSI catcher |
| `CELL_JAM` | TETRA, PMR446 | 392 / 446 MHz | Mobile network / tactical jamming |
| `IOT_REPLAY` | ISM433 | 433 MHz | IoT signal replay attack |
| `LORA_SKIM` | ISM868, ISM915 | 868 / 915 MHz | LoRa network attack |
| `DRONE_FHSS` | DRONE 2.4G / 5.8G | 2440 / 5800 MHz | FHSS drone control (DJI/ELRS) |
| `WIFI_DEAUTH` | WiFi 2.4G CH6, BT | 2437 / 2480 MHz | Wi-Fi deauth / BT flooding |
| `ADSB_SPOOF` | ADS-B 1090 | 1090 MHz | Spoofed ADS-B aircraft signal |
| `SATCOM` | Sat L-band | 1545 MHz | Satellite band anomaly |
| `EMERGENCY` | UHF/VHF Emerg | 457 / 155 MHz | Emergency channel jamming |

Each threat type has its own rule engine in `analyze()` and a dedicated AI model in `RFAnomalyAI`.

---

## Web UI

Access: `http://127.0.0.1:1717/`

| Feature | Description |
|---|---|
| **Dashboard** | Donut chart (threat types), line chart (power timeline), bar chart (hourly activity) |
| **Heatmap** | Activity by frequency band |
| **Real-time** | SSE `/api/stream` — pushed immediately on each new event |
| **Filter** | By severity, threat type, channel, time range |
| **Export** | `/api/export?format=csv` or `?format=json` |
| **Calibration** | Per-band offset wizard, toggle CALIBRATION_VERIFIED |
| **RF Model** | Accuracy, classes, degenerate status |
| **Channels** | Baseline and last Z-score for each watchlist channel |

### API endpoints

```
GET  /                            → Dashboard HTML
GET  /api/events                  → Recent events (JSON)
GET  /api/stream                  → SSE stream (text/event-stream)
GET  /api/export?format=csv|json  → Full event history export
GET  /api/calibration             → Read current offsets
POST /api/calibration             → Update offsets (body: {bands: [...]})
GET  /api/channels                → Status of each watchlist channel
GET  /vendor/chart.js             → Chart.js local copy (offline fallback)
```

> **Security**: The UI binds to `127.0.0.1:1717` (localhost only) by default. Do **not** expose it to the internet without authentication and TLS (e.g., nginx reverse proxy with Basic Auth).

---

## Agent Layer

`rf_sentinel_agents.py` provides six agents orchestrated by `AgentSuite`:

### 1. SimpleSOM — Self-Organizing Map
An 8×8 neuron SOM with online learning. Each event is mapped to its best matching unit (BMU); large BMU distance signals a high anomaly score.

### 2. TeacherStudentBridge — Semi-supervised
Uses labeled events as a "teacher" to pseudo-label unlabeled events via kNN. Results feed into the RF classifier.

### 3. CognitiveFrequencyAgent — Frequency tracking
Tracks power history per frequency and time slot. Detects drift, burst patterns, and novel frequencies.

### 4. ActiveLearningAgent — Active Learning
Selects the events most in need of labeling (highest uncertainty + diversity) and writes them to `active_learning_queue.json` for operator review.

### 5. AutomatedResponseAgent — Alert & Response
On threat ≥ HIGH:
- Sends webhooks (Telegram / Discord / Slack)
- Generates a PDF incident report (requires `reportlab`)
- Executes `RF_RESPONSE_SCRIPT` if configured

### 6. ProtocolDecoderAgent — Protocol decoding
Demodulates FSK / OOK / BPSK from saved IQ snapshots. Outputs raw protocol frames to `evidence/` and JSON.

### BearingEstimator (helper)
Estimates signal bearing (AoA / RSSI) from single-station measurements over time.

---

## Architecture

### Module overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        SDR-BLUE-TEAM.py                         │
│  (Core: DSP + AI + DB + sweep loop + Flask glue)                │
│                                                                 │
│  ┌────────────────┐  ┌───────────────────┐  ┌───────────────┐  │
│  │ Signal Process │  │   AI / Detection  │  │   Database    │  │
│  │ ─────────────  │  │  ─────────────── │  │  ──────────── │  │
│  │ FFT / PSD      │  │ HybridCognitiveAI │  │ SQLite CRUD   │  │
│  │ Savitzky-Golay │  │ RFAnomalyAI       │  │ auto-label    │  │
│  │ DTW FHSS       │  │ RFThreatClassifier│  │ spectrum hist │  │
│  │ CAF cylostat.  │  │ PersistenceTracker│  │ export        │  │
│  └────────────────┘  └───────────────────┘  └───────────────┘  │
│                                                                 │
│  ┌────────────────┐  ┌───────────────────┐  ┌───────────────┐  │
│  │  Hardware I/O  │  │   Sweep / Monitor │  │  TX-Guard     │  │
│  │  ────────────  │  │  ──────────────── │  │  ──────────── │  │
│  │ FastSweepEngine│  │ monitor_loop()    │  │ RxOnlyProxy   │  │
│  │ EngineHandle   │  │ sweep_once()      │  │ verify_hash   │  │
│  │ connect_hackrf │  │ init_baseline()   │  │ TransmitBlock │  │
│  └────────────────┘  └───────────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────────────┘
         │ DI (dependency injection)          │ DI
         ▼                                    ▼
┌──────────────────────┐          ┌────────────────────────────┐
│  rf_sentinel_ui.py   │          │  rf_sentinel_agents.py     │
│  ─────────────────── │          │  ─────────────────────────  │
│  register(app, fns)  │          │  AgentSuite.on_event()     │
│  Flask routes        │          │  SimpleSOM                 │
│  SSE broadcaster     │          │  TeacherStudentBridge      │
│  Dashboard HTML      │          │  CognitiveFrequencyAgent   │
│                      │          │  ActiveLearningAgent       │
│                      │          │  AutomatedResponseAgent    │
│                      │          │  ProtocolDecoderAgent      │
└──────────────────────┘          └────────────────────────────┘
```

### Signal processing & detection pipeline

```
HackRF One
    │  IQ samples (2 MSPS, FFT_SIZE=1024)
    ▼
ReceiveOnlySDRProxy          ← TX-Guard: any TX call → immediate abort
    │
    ▼
FastSweepEngine              ← ~25 ms/channel, rolling through WATCHLIST
    │
    ▼
Signal Processing Pipeline
  ├─ iq_bytes_to_complex()
  ├─ estimate_power_dbm()    ← apply calibration offset
  ├─ smooth_psd_savgol()     ← [C] Savitzky-Golay pre-filter
  ├─ compute_psd()           ← FFT → Power Spectral Density
  ├─ spectral_entropy()
  ├─ kurtosis_of()
  ├─ sample_entropy_of()
  ├─ stft_entropy()
  ├─ cyclostationary_score() ← CAF basic
  ├─ cyclo_detect_advanced() ← [D] CAF advanced, multi symbol-rate
  └─ FHSSTracker.update()    ← [B] DTW centroid history → FHSS score
    │
    ▼
Dual-AI Detection
  ├─ HybridCognitiveAI        ← AI [1] Global: DBSCAN + IsolationForest
  │    (all channels at once — detects anomalous clusters)
  └─ RFAnomalyAI              ← AI [2] Per-type: HMM / LOF / OCSVM / IF
       (each threat_type has its own model)
    │
    ▼
analyze() → ThreatResult
  ├─ Per-threat-type rule engine (GPS_JAM, FAKE_BTS, DRONE_FHSS…)
  ├─ EW_AnomalyResult (scores from both AIs)
  └─ fingerprint()            ← store RF fingerprint per channel
    │
    ▼
Confidence Gates
  ├─ [Gate 1] PersistenceTracker   ← ≥3/5 rounds
  ├─ [Gate 2] Critical Z-score     ← must exceed threshold
  ├─ [Gate 3] EMA drift            ← must show trend
  └─ [Gate 4] RF downgrade-only    ← RF may only lower threat level, not raise it
    │
    ▼
RFThreatClassifier (AI [3] Supervised)
  ├─ RandomForest / LightGBM / XGBoost
  ├─ Activates after ≥ 200 labeled events
  ├─ Guards against label leakage (max class share ≤ 85%)
  └─ Auto-detects rule-table copy model → marks UNUSABLE
    │
    ▼
Event Persistence (SQLite)
  ├─ db_log_event()
  ├─ save_evidence()          ← save IQ snapshot (.sigmf) + PNG spectrogram
  └─ _auto_label()            ← auto-assign LOW/MEDIUM+ when confidence is high
    │
    ▼
Output
  ├─ Logger (sentinel.log, rotating 8 MB × 4)
  ├─ Flask Web UI :1717       ← SSE real-time push
  ├─ AgentSuite               ← 6 agents running in parallel
  └─ Wideband survey          ← 300–1000 MHz every 40 sweep rounds
```

### Key classes

**`Channel`** (dataclass)

```python
@dataclass
class Channel:
    name: str              # "GPS_L1"
    freq_hz: float         # 1575.42e6
    priority: int          # 1=critical, 2=medium, 3=low
    threat_type: str       # "GPS_JAM"
    baseline_mean: float   # EMA mean power
    baseline_std: float    # EMA std power
    z_score: float         # Z-score from last scan
    fhss_score: float      # DTW FHSS score
    last_power: float      # power (dBm) from last scan
    scan_count: int        # total scan count
```

**`ThreatResult`** (dataclass)

```python
@dataclass
class ThreatResult:
    channel: Channel
    threat_level: ThreatLevel      # OK/LOW/MEDIUM/HIGH/CRITICAL
    threat_type: str               # "GPS_JAM", "FAKE_BTS"…
    confidence: float              # 0.0–1.0
    anomaly_score: float           # composite anomaly score
    ew_result: EW_AnomalyResult    # detailed AI scores
    rule_flags: dict               # flags from the rule engine
    timestamp: str                 # ISO 8601 UTC
```

**`HybridCognitiveAI`** — AI [1]

```
Features: [power_z, entropy, kurtosis, sample_entropy, stft_entropy, cyclo, fhss]

Online:
  ├─ EMA baseline update (every EMA_UPDATE_INTERVAL_S seconds)
  └─ Z-score on sliding window

Batch (every N events):
  ├─ DBSCAN → cluster outlier score
  └─ IsolationForest → anomaly score

Output: float 0–1
```

**`RFAnomalyAI`** — AI [2]

```
Per threat_type, different model:
  DRONE_FHSS / GPS_SPOOF  → HMM (hmmlearn)
  IOT_REPLAY / LORA_SKIM / FAKE_BTS → LOF (LocalOutlierFactor)
  EMERGENCY               → OCSVM (OneClassSVM)
  * (default)             → IsolationForest

Online: buffer features, fit when MIN_SAMPLES reached
Output: float 0–1
```

**`RFThreatClassifier`** — AI [3]

```
Input: labeled events from DB
Features: 12 DSP + AI score features

Guards:
  ├─ < RF_MIN_TRAINING (200) rows → SKIP
  ├─ < 2 classes → SKIP
  ├─ any class > RF_MAX_CLASS_SHARE (85%) → SKIP
  └─ CV5 score > RF_RULE_TABLE_CEILING (0.97) → DEGENERATE / UNUSABLE

Backend (auto-select): LightGBM > XGBoost > RandomForest
Retrain: every RF_RETRAIN_EVERY_N (500) new labeled events
```

### Database schema (SQLite)

```sql
CREATE TABLE events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,       -- ISO 8601 UTC
    channel      TEXT NOT NULL,       -- "GPS_L1"
    threat_type  TEXT NOT NULL,       -- "GPS_JAM"
    level        TEXT NOT NULL,       -- "HIGH"
    confidence   REAL,
    power_dbm    REAL,
    zscore       REAL,
    anomaly_scr  REAL,
    global_scr   REAL,
    type_scr     REAL,
    entropy      REAL,
    kurtosis     REAL,
    cyclo_scr    REAL,
    fhss_scr     REAL,
    persist_ratio REAL,
    iq_path      TEXT,                -- path to .iq file in evidence/
    confirmed    INTEGER DEFAULT NULL -- NULL=unreviewed, 1=TP, 0=FP
);

CREATE TABLE labeled_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT,
    channel     TEXT,
    threat_type TEXT,
    label       TEXT NOT NULL,        -- label assigned by operator or auto-label
    power_dbm   REAL,
    -- … same DSP features as events
    source      TEXT DEFAULT 'auto'   -- 'auto' / 'operator'
);

CREATE TABLE spectrum_history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT,
    channel   TEXT,
    power_dbm REAL
    -- indexed on (channel, ts) for timeline queries
);
```

### Dependency injection pattern

To avoid circular imports between the three main modules, RF Sentinel uses dependency injection:

```
SDR-BLUE-TEAM.py  →  rf_sentinel_ui.py
                       register(app, fn1, fn2, …)
                       # fn1, fn2 = functions from core
                       # rf_sentinel_ui does NOT import core

SDR-BLUE-TEAM.py  →  rf_sentinel_agents.py
                       AgentSuite(sdr_handle, db_fn, …)
                       # rf_sentinel_agents does NOT import core
```

Rule: **child modules must not import the parent module.**

### report_error protocol

`report_error(where, exc, every=30.0, level="error")` is the only function allowed to handle exceptions without re-raising. Design:

```
Dedup: same `where` within `every` seconds → count "folded", do not log again
Output: "rf_sentinel" logger if handlers present; stderr otherwise
Format: "[ERR] where: ExcType: message [file:line in func] (+N folded)"

Byte-identical copy in all three files:
  SDR-BLUE-TEAM.py    (primary)
  rf_sentinel_agents.py
  rf_sentinel_ui.py
```

### SSE architecture

```
detect event
    │
    ▼
broadcast_sse(data)
    ├─ _ensure_broadcaster()    # start broadcaster thread if not running
    └─ _sse_queue.put(data)     # thread-safe queue
              │
              ▼
    _broadcaster_loop()         # daemon thread
         ├─ _sse_queue.get()    # block until event available
         └─ push to all _sse_clients
                    │
                    ▼
         /api/stream (Flask)
              └─ yield f"data: {json}\n\n"
                   └─ browser receives → updates charts in real time
```

### Source files

| File | Role | Lines |
|---|---|---|
| `SDR-BLUE-TEAM.py` | Core: DSP, AI, DB, sweep loop, Flask glue | ~3300 |
| `rf_sentinel_agents.py` | 6 agent plugins | ~1300 |
| `rf_sentinel_ui.py` | Flask routes, SSE broadcaster, dashboard HTML | ~900 |
| `test_sdr_sentinel.py` | Unittest suite (20+ classes, no hardware) | ~2000 |
| `check_no_swallow.py` | CI linter — detects silently-swallowed errors | ~300 |

---

## Testing

Run the full suite (no HackRF required):

```bash
python test_sdr_sentinel.py           # all tests
python test_sdr_sentinel.py -v        # verbose mode
python test_sdr_sentinel.py TestDSP   # run only the DSP group
```

| Test class | Coverage |
|---|---|
| `TestDSP` | FFT, entropy, kurtosis, cyclostationary |
| `TestChannel` | Baseline tracking, Z-score |
| `TestThreatRules` | Per-threat detection rules in `analyze()` |
| `TestConfidenceGates` | PersistenceTracker, apply_confidence_gate |
| `TestRXGuard` | ReceiveOnlySDRProxy blocks TX |
| `TestRFClassifier` | RF gating, training guards, leakage detection |
| `TestDatabase` | SQLite CRUD with in-memory DB |
| `TestReportError` | report_error dedup, folding, level |
| `TestNoSilentFailures` | check_no_swallow run against the codebase itself |
| `TestMainSurfacesWorkerFailure` | Exceptions in sweep thread bubble up to main |
| `TestAgentsNoSilentFailure` | Agents do not silently swallow errors |

---

## CI — check_no_swallow

```bash
python check_no_swallow.py                  # scan all default targets
python check_no_swallow.py path/to/file.py  # scan a specific file
```

Exit code 0 = clean, 1 = violations found. Integrate into pre-commit or CI:

```yaml
# .github/workflows/lint.yml
- name: No silent failures
  run: python check_no_swallow.py
```

**Violation types detected**

| Type | Description |
|---|---|
| `SILENT` | `except: pass / continue / break` |
| `FALLBACK-NO-REPORT` | Assigns a fallback value without reporting the error |
| `DEBUG-ONLY` | Only logs at `debug` level (invisible at default INFO) |
| `BARE-EXCEPT` | `except:` with no type (catches `KeyboardInterrupt`) |
| `SUPPRESS` | `contextlib.suppress(…)` |
| `JS-SWALLOW` | JavaScript `catch {}` in dashboard HTML without error reporting |

**NO SILENT FAILURES rule**

Every `except` block must do at least one of:
- Re-raise (`raise`)
- Call `report_error(where, exc)`
- Log at WARNING level or higher

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

# ✅ Correct — expected control flow with marker
try:
    item = q.get(timeout=1.0)
except queue.Empty:  # expected-exception: idle poll
    continue

# ❌ Wrong — silent swallow
try:
    something()
except ValueError:
    pass
```

---

## Warnings & Limitations

> ⚠️ **CALIBRATION**: dBm values are relative until you run a calibration pass.

> ⚠️ **FHSS TEMPLATES**: DJI/ELRS templates are synthetic data, not captured from real hardware. Recognition accuracy depends on your environment; replace with real templates for best results.

> ⚠️ **SWEEP SPEED**: ~25 ms/channel. Very short bursts (< 5 ms) may be missed.

> ⚠️ **DSSS**: Spread-spectrum signals below the noise floor (e.g., GPS L1 C/A) may not be detected.

> ⚠️ **PASSIVE TOOL**: No transmit, no replay, no injection. TX-Guard aborts the program immediately if any TX call is made.

---

## Directory Structure

```
rf-sentinel/
├── SDR-BLUE-TEAM.py           # Core — entry point
├── rf_sentinel_agents.py      # 6 agent plugins
├── rf_sentinel_ui.py          # Flask web UI
├── test_sdr_sentinel.py       # Test suite
├── check_no_swallow.py        # CI linter
├── requirements.txt           # All dependencies (hard + optional)
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── PULL_REQUEST_TEMPLATE.md
├── udev/
│   └── 53-hackrf.rules        # Linux USB permissions
├── vendor/
│   └── chart.umd.min.js       # Chart.js local copy (offline fallback)
└── rf_logs/                   # Created at runtime
    ├── sentinel.log
    ├── rf_sentinel.db
    ├── rf_threat_clf.joblib
    ├── fingerprints/
    ├── evidence/
    └── reports/
```

---

## Changelog

### [15.0.0] — ADV-PATCH-v1 (Current)

**Security / Safety**
- **TX-Guard**: added `verify_rx_guard_integrity()` with SHA-256 self-hash and runtime self-test — aborts immediately if the proxy is bypassed.
- **ReceiveOnlySDRProxy**: full list of blocked TX attributes: `transmit`, `tx_*`, `set_tx_*`, `start_tx`, `hackrf_start_tx`.

**Bug Fixes**
- **RF_CLF initialization order**: `RFThreatClassifier` is no longer created at module scope — avoids crash when `logger` does not yet exist. Moved to lazy init via `_get_rf()` / `init_rf()`, called from `main()` after `logger` and `init_db()`.
- **Flask reloader**: `WEB_APP.run()` now uses `use_reloader=False, debug=False`, running in a daemon thread instead of a forked process — eliminates double-HackRF / double-SQLite when Flask's reloader forks. Added `WERKZEUG_RUN_MAIN` env guard and `--web-only` flag.
- **RF training label leakage**: refuses training if one class exceeds `RF_MAX_CLASS_SHARE` (85%); detects rule-table copy models (CV5 > `RF_RULE_TABLE_CEILING` 0.97) and marks them `DEGENERATE / UNUSABLE`.

**New Features**
- **Wideband survey**: scans 300–1000 MHz (8 MHz step) every 40 rounds, discovers new channels outside the watchlist via `CandidateTracker`.
- **[C] Savitzky-Golay spectrum pre-filter**: smooths PSD before Z-score calculation to reduce false positives from noise spikes.
- **[B] DTW FHSS tracker**: `FHSSTracker` tracks centroid history over 24 snapshots; DTW distance matches FHSS patterns (DJI/ELRS).
- **[D] Advanced CAF cyclostationary**: `cyclo_detect_advanced()` probes 8 symbol rates, detects modulated signals with clear cyclostationary features.
- **[A] LightGBM / XGBoost backend**: auto-selects LightGBM (or XGBoost) over RandomForest when installed; same API.
- **`--web-only` flag**: debug Flask without opening hardware.
- **`--train-now` flag**: force RF model retrain on startup.
- **Wideband GUI**: matplotlib spectrum GUI runs in a separate subprocess, never blocking the sweep loop.
- **`_THIS_DIR` anchoring**: all paths (rf_logs/, model, DB) are anchored to the script directory, independent of CWD.
- **Module override system**: `_MODULE_OVERRIDES` allows swapping backends without modifying source.

**Agent Layer** (`rf_sentinel_agents.py`)
- **SimpleSOM**: 8×8 Self-Organizing Map, online learning, anomaly score from BMU distance.
- **TeacherStudentBridge**: semi-supervised from labeled events → pseudo-labels for unlabeled data.
- **CognitiveFrequencyAgent**: tracks power history per frequency, detects drift and burst.
- **ActiveLearningAgent**: margin sampling + diversity → `active_learning_queue.json`.
- **AutomatedResponseAgent**: Telegram/Discord/Slack webhooks, PDF reports (reportlab), `RF_RESPONSE_SCRIPT`.
- **ProtocolDecoderAgent**: demodulates FSK/OOK/BPSK from IQ snapshots → SigMF output.
- **BearingEstimator**: RSSI-based AoA from a single station.
- **AgentSuite**: orchestration with per-agent try/except + report_error (agent crash does not kill sweep).

**Web UI** (`rf_sentinel_ui.py`)
- Fully separated from `SDR-BLUE-TEAM.py` into its own file.
- Dependency injection via `register()` — avoids circular imports.
- Chart.js: donut (threat types), line (power timeline), bar (hourly activity).
- Frequency heatmap by band.
- SSE `/api/stream` — real-time push without page reload.
- CSV / JSON export of full event history.
- Calibration wizard — per-band offset entry, toggle CALIBRATION_VERIFIED.
- RF model panel: accuracy, feature importance, degenerate flag.
- Channel panel: baseline, last Z-score, FHSS score.
- Filters: severity, threat type, channel name, time range.
- Chart.js local fallback at `/vendor/chart.js` (works offline).

**Testing**
- `test_sdr_sentinel.py` expanded to 20+ test classes, zero hardware required.
- `TestNoSilentFailures`: runs `check_no_swallow.py` against the full codebase.
- `TestMainSurfacesWorkerFailure`: exceptions in the sweep thread must bubble up to main.
- `TestAgentsNoSilentFailure`: every agent exception must be logged.
- `TestUIFailuresAreLoud`: Flask route exceptions must not be swallowed.

**Tooling**
- `check_no_swallow.py`: AST analysis for SILENT, FALLBACK-NO-REPORT, DEBUG-ONLY, BARE-EXCEPT, SUPPRESS, JS-SWALLOW.
- `default_targets()`: auto-discovers targets in both flat (dev) and repo (production) layouts.
- `EXPECTED_TYPES`: allows marking valid exception control-flow with an `# expected-exception:` marker.

### [14.x] — Previous versions

Detailed history for 14.x and earlier is not retained in the current repo.

**Key differences vs v14**
- v14: `RFThreatClassifier` created at module scope → crash if logger not ready.
- v14: Flask with `debug=True` → reloader fork doubled HackRF connection.
- v14: no FHSS tracker, no wideband survey.
- v14: Flask UI embedded in `SDR-BLUE-TEAM.py` as a string → hard to maintain.
- v14: no agent layer.
- v14: no `check_no_swallow.py`.

---

## License

BSD 3-Clause License

Copyright (c) 2024, RF Sentinel Contributors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the project nor the names of its contributors may be
   used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.










---


**GUERILLA OPEN SOURCE MANIFESTO**


Information is power. But like all power, there are those who want to keep it for 
themselves. The world's entire scientific and cultural heritage, published over centuries 
in books and journals, is increasingly being digitized and locked up by a handful of 
private corporations. Want to read the papers featuring the most famous results of the 
sciences? You'll need to send enormous amounts to publishers like Reed Elsevier. 

There are those struggling to change this. The Open Access Movement has fought 
valiantly to ensure that scientists do not sign their copyrights away but instead ensure 
their work is published on the Internet, under terms that allow anyone to access it. But 
even under the best scenarios, their work will only apply to things published in the future. 
Everything up until now will have been lost. 

That is too high a price to pay. Forcing academics to pay money to read the work of their 
colleagues? Scanning entire libraries but only allowing the folks at Google to read them? 
Providing scientific articles to those at elite universities in the First World, but not to 
children in the Global South? It's outrageous and unacceptable. 

"I agree," many say, "but what can we do? The companies hold the copyrights, they 
make enormous amounts of money by charging for access, and it's perfectly legal — 
there's nothing we can do to stop them." But there is something we can, something that's 
already being done: we can fight back. 

Those with access to these resources — students, librarians, scientists — you have been 
given a privilege. You get to feed at this banquet of knowledge while the rest of the world 
is locked out. But you need not — indeed, morally, you cannot — keep this privilege for 
yourselves. You have a duty to share it with the world. And you have: trading passwords 
with colleagues, filling download requests for friends. 



Meanwhile, those who have been locked out are not standing idly by. You have been 
sneaking through holes and climbing over fences, liberating the information locked up by 
the publishers and sharing them with your friends. 

But all of this action goes on in the dark, hidden underground. It's called stealing or 
piracy, as if sharing a wealth of knowledge were the moral equivalent of plundering a 
ship and murdering its crew. But sharing isn't immoral — it's a moral imperative. Only 
those blinded by greed would refuse to let a friend make a copy. 

Large corporations, of course, are blinded by greed. The laws under which they operate 
require it — their shareholders would revolt at anything less. And the politicians they 
have bought off back them, passing laws giving them the exclusive power to decide who 
can make copies. 

There is no justice in following unjust laws. It's time to come into the light and, in the 
grand tradition of civil disobedience, declare our opposition to this private theft of public 
culture. 

We need to take information, wherever it is stored, make our copies and share them with 
the world. We need to take stuff that's out of copyright and add it to the archive. We need 
to buy secret databases and put them on the Web. We need to download scientific 
journals and upload them to file sharing networks. We need to fight for Guerilla Open 
Access. 

With enough of us, around the world, we'll not just send a strong message opposing the 
privatization of knowledge — we'll make it a thing of the past. Will you join us? 

Aaron Swartz 

July 2008, Eremo, Italy 

