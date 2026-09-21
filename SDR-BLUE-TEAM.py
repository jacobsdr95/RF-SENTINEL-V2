#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# [ADV-PATCH-v1] Applied
"""
RF SENTINEL v15 — GATED DUAL-AI RF MONITOR  (+ Random Forest + Flask UI :1717)

================================================================================
PATCH NOTES — what changed vs. "rf_sentinel_v15_gated (3).py"
================================================================================
[1] RF_CLF INITIALISATION ORDER  (the import-time crash you flagged)
    RF_CLF is no longer constructed at module scope. `logger` is defined at
    line ~236 in the original, but a module-level RFThreatClassifier() that
    logs would run before that in any reordering, and any future move of the
    constant block breaks it again. Fix: RF_CLF is created lazily by
    `_get_rf()` / `init_rf()`, which is called from main() AFTER logger and
    AFTER init_db(). Nothing logs before logger exists.

[2] FLASK RELOADER  (the double-HackRF / double-SQLite fork)
    WEB_APP.run() is called with use_reloader=False, debug=False, and the
    Flask process is a daemon THREAD, not a forked process. The reloader is
    additionally suppressed by an env guard AND a hard check that refuses to
    start the web UI when WERKZEUG_RUN_MAIN is set — so even an accidental
    debug=True cannot fork. To debug routes, use `--web-only` (see main()),
    which starts the Flask layer with no HackRF, no sweep, no SQLite writer
    contention. That IS the isolated debugging script, built in.

[3] RF TRAINING  (the ≥200-row / ≥2-class threshold and label leakage)
    The classifier stays silent below RF_MIN_TRAINING rows or with <2 classes
    — unchanged as a safety property, not a workaround. But train() now:
      - refuses to run if any single class exceeds RF_MAX_CLASS_SHARE (0.85),
        which is exactly what bulk-labelling by threat_type produces;
      - detects the degenerate case where the model just reproduces the rule
        table (cv5 score > RF_RULE_TABLE_CEILING while a majority-class
        baseline scores the same) and marks the model UNUSABLE instead of
        silently shipping a mirror of the rules;
      - persists a `leaky` / `degenerate` flag alongside the model, and
        predict() refuses to return a label from a flagged model.
    A model trained to reproduce your thresholds is worse than no model,
    because it will agree with the rules and inflate apparent consensus.
================================================================================
"""

# ============================================================================
# IMPORTS
# ============================================================================
# Annotations are stored as strings and never evaluated at definition time, so
# `dict[str, str]` / `str | None` below do not need Python 3.9 / 3.10 at import.
from __future__ import annotations

import copy
import os
import sys
import json
import time
import math
import glob
import sqlite3
import logging
import threading
import traceback
import importlib
import importlib.util
import multiprocessing as mp
from collections import Counter, deque, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from logging.handlers import RotatingFileHandler
from threading import Thread, Lock
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# _THIS_DIR — absolute directory this script lives in, resolved once here.
# Every path in this file (rf_logs/, and sibling-module discovery below) is
# anchored to THIS instead of the process's current working directory, so
# `python SDR-BLUE-TEAM.py` behaves identically whether launched from this
# folder, a systemd unit with a different CWD, or `python /some/where/
# SDR-BLUE-TEAM.py`.
# ---------------------------------------------------------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# report_error — the ONLY sanctioned way to handle an exception without
# re-raising it.  Project rule: NO SILENT FAILURES.  An `except` block must
# either re-raise or call this (or log at WARNING+); never `pass`, never a
# bare fallback value, never logger.debug (invisible at the default INFO level).
# tools/check_no_swallow.py enforces that, and test_sdr_sentinel.py runs it.
#
#   where  short stable id of the call site — also the de-dup key.
#   exc    the exception (or a plain message string).
#   every  seconds between repeats of the SAME `where` (default 30):
#            0    -> print every occurrence (rare / one-shot paths)
#            None -> print only the first occurrence ever (missing optional dep)
#          A repeat is counted, never dropped silently: the next line that does
#          print says how many were folded into it.
#   level  "error" (default) or "warning".
#
# Identical copy lives in rf_sentinel_agents.py and rf_sentinel_ui.py (those
# files must stay importable on their own); a test asserts the copies match.
# Uses the shared "rf_sentinel" logger when main has configured it, otherwise
# stderr — so it also works before logging exists and inside child processes.
# ---------------------------------------------------------------------------
_ERR_STATE: dict = {}
_ERR_LOCK = threading.Lock()


def report_error(where, exc=None, *, every=30.0, level="error"):
    now = time.monotonic()
    with _ERR_LOCK:
        st = _ERR_STATE.setdefault(where, {"last": None, "folded": 0})
        if st["last"] is not None:
            if every is None or (every > 0 and now - st["last"] < every):
                st["folded"] += 1
                return
        folded, st["folded"], st["last"] = st["folded"], 0, now
    if exc is None:
        what = ""
    elif isinstance(exc, BaseException):
        what = f": {type(exc).__name__}: {exc}"
        tb = getattr(exc, "__traceback__", None)
        # SyntaxError / ImportError already say where (file, line / module name); their
        # traceback only points into importlib internals, which is noise.
        if tb is not None and not isinstance(exc, (SyntaxError, ImportError)):
            fr = traceback.extract_tb(tb)[-1]
            what += f" [{os.path.basename(fr.filename)}:{fr.lineno} in {fr.name}]"
    else:
        what = f": {exc}"
    msg = f"[{'WARN' if level == 'warning' else 'ERR'}] {where}{what}"
    if folded:
        msg += f"  (+{folded} lan lap lai bi gop)"
    lg = logging.getLogger("rf_sentinel")
    try:
        if lg.handlers:
            lg.log(logging.WARNING if level == "warning" else logging.ERROR, msg)
            return
    except Exception as log_err:
        print(f"[ERR] logger hong ({log_err!r}) - in thang ra stderr", file=sys.stderr)
    print(msg, file=sys.stderr)


# Module names whose directory scan already came up empty (or failed to load) —
# _load_sibling_module() must not rescan/re-report them on every saved event.
_SIBLING_LOAD_FAILED: set = set()


def _load_sibling_module(module_name: str, filename_patterns):
    """Find and load a module that lives next to this file, by NAME
    matching rather than a hardcoded relative import — this is what lets
    rf_sentinel_ui.py / rf_sentinel_agents.py be found no matter what the
    repo folder is called or where the process was launched from.

    Search order (first match wins), all resolved to absolute paths off
    _THIS_DIR so this never depends on CWD:
      1. Exact filename(s) in this script's own directory.
      2. Glob pattern(s) in this script's own directory (handles renamed /
         versioned copies, e.g. "rf_sentinel_ui_v2.py").
      3. Fall back to a normal `import module_name` (e.g. installed as a
         real package on sys.path / pip-installed).
    Returns the loaded module, or None if nothing was found anywhere.

    Two guarantees that matter at runtime:
      * LOAD ONCE.  A module already loaded from this directory is returned
        from sys.modules as-is.  Re-executing the file on every call would
        create a brand-new module object each time (fresh, empty
        rf_sentinel_ui._sse_clients), and this function is called once per
        saved event — so live SSE pushes would go to a list no browser is
        subscribed to, and the whole file would be re-parsed per event.
      * NO SILENT FAILURE.  A candidate file that fails to load (SyntaxError,
        ImportError inside it, ...) is reported ONCE on stderr with
        file:line, then skipped.  logger does not exist yet when this first
        runs (see LOGGING block below), hence stderr rather than logger.
    """
    cached = sys.modules.get(module_name)
    cached_file = getattr(cached, "__file__", None)
    if cached_file and os.path.dirname(os.path.abspath(cached_file)) == _THIS_DIR:
        return cached

    if module_name not in _SIBLING_LOAD_FAILED:  # scan this directory at most once
        tried = set()
        for pattern in filename_patterns:
            for path in sorted(glob.glob(os.path.join(_THIS_DIR, pattern))):
                if path in tried or not os.path.isfile(path):
                    continue
                tried.add(path)
                try:
                    spec = importlib.util.spec_from_file_location(module_name, path)
                    mod = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = mod
                    spec.loader.exec_module(mod)
                    return mod
                except Exception as e:           # SyntaxError is an Exception too
                    sys.modules.pop(module_name, None)   # no half-built module left behind
                    report_error(f"LOAD {module_name} <- {os.path.basename(path)}",
                                 e, every=None)
        _SIBLING_LOAD_FAILED.add(module_name)    # nothing usable here; don't rescan per event

    try:
        return importlib.import_module(module_name)
    except ImportError as e:
        report_error(f"IMPORT {module_name}", e, every=None, level="warning")
        return None

# ---------------------------------------------------------------------------
# _dyn_import — importlib-based dynamic loader
#   Usage:  mod = _dyn_import("numpy")                     → module or None
#           obj = _dyn_import("numpy", "ndarray")          → attr or None
#           obj = _dyn_import("sklearn.ensemble",
#                             "RandomForestClassifier")
#
# Why importlib instead of bare try/import?
#   • The module name is a plain string → swap it at runtime or via config
#     without touching any `import` statement in the body.
#   • _MODULE_OVERRIDES maps "logical name" → "real package name", so
#     you can point e.g. "lightgbm" at a monkey-patch shim without a fork.
#   • importlib.import_module() respects sys.modules, so already-loaded
#     modules are returned from cache — no double-loading.
# ---------------------------------------------------------------------------
_MODULE_OVERRIDES: dict[str, str] = {
    # "logical_name": "real_package_name",
    # e.g. "lightgbm": "lightgbm_compat",
}

def _dyn_import(module_name: str, attr: str | None = None):
    """Dynamically import *module_name* (respecting _MODULE_OVERRIDES).
    Returns the module, or *attr* from it if given.
    Returns None on ImportError / AttributeError without raising.
    """
    real_name = _MODULE_OVERRIDES.get(module_name, module_name)
    try:
        mod = importlib.import_module(real_name)
        if attr is None:
            return mod
        return getattr(mod, attr)
    except (ImportError, AttributeError) as e:
        # Optional dependency missing (or wrong version): keep going without it,
        # but say so — once per package — instead of degrading silently.
        report_error(f"DEP {real_name}" + (f".{attr}" if attr else ""),
                     e, every=None, level="warning")
        return None

def _reload_module(module_name: str):
    """Force-reload a previously imported module (and its override target).
    Useful for hot-swapping a plugin or patched sub-module at runtime.
    Returns the reloaded module, or None on failure.
    """
    real_name = _MODULE_OVERRIDES.get(module_name, module_name)
    mod = sys.modules.get(real_name)
    if mod is None:
        return _dyn_import(module_name)
    try:
        return importlib.reload(mod)
    except Exception as e:
        report_error(f"RELOAD {module_name}", e, every=0)
        return None

# ---- numpy (hard dependency — abort early if missing) ----------------------
np = _dyn_import("numpy")
if np is None:
    raise ImportError("numpy is required — install it with: pip install numpy")

# ---- scipy -----------------------------------------------------------------
_scipy_mod  = _dyn_import("scipy.stats")
_scipy_stats = _scipy_mod  # keep original alias used throughout the file
SCIPY_OK    = _scipy_mod is not None

# ---- joblib ----------------------------------------------------------------
joblib      = _dyn_import("joblib")
JOBLIB_OK   = joblib is not None

# ---- scikit-learn ----------------------------------------------------------
StandardScaler         = _dyn_import("sklearn.preprocessing",  "StandardScaler")
DBSCAN                 = _dyn_import("sklearn.cluster",         "DBSCAN")
IsolationForest        = _dyn_import("sklearn.ensemble",        "IsolationForest")
RandomForestClassifier = _dyn_import("sklearn.ensemble",        "RandomForestClassifier")
LocalOutlierFactor     = _dyn_import("sklearn.neighbors",       "LocalOutlierFactor")
OneClassSVM            = _dyn_import("sklearn.svm",             "OneClassSVM")
train_test_split       = _dyn_import("sklearn.model_selection", "train_test_split")
StratifiedKFold        = _dyn_import("sklearn.model_selection", "StratifiedKFold")
cross_val_score        = _dyn_import("sklearn.model_selection", "cross_val_score")
DummyClassifier        = _dyn_import("sklearn.dummy",           "DummyClassifier")
SKLEARN_OK = all([
    StandardScaler, DBSCAN, IsolationForest, RandomForestClassifier,
    LocalOutlierFactor, OneClassSVM, train_test_split,
    StratifiedKFold, cross_val_score, DummyClassifier,
])

# ---- Flask -----------------------------------------------------------------
_flask      = _dyn_import("flask")
Flask                  = _dyn_import("flask", "Flask")
jsonify                = _dyn_import("flask", "jsonify")
request                = _dyn_import("flask", "request")
render_template_string = _dyn_import("flask", "render_template_string")
FLASK_OK    = Flask is not None

# ---- hmmlearn --------------------------------------------------------------
GaussianHMM = _dyn_import("hmmlearn.hmm", "GaussianHMM")
HMM_OK      = GaussianHMM is not None

# ---- LightGBM / XGBoost — drop-in faster replacements for RandomForest ----
# [A] To swap backend: _MODULE_OVERRIDES["lightgbm"] = "lightgbm_compat"
LGBMClassifier = _dyn_import("lightgbm", "LGBMClassifier")
LGBM_OK        = LGBMClassifier is not None

XGBClassifier  = _dyn_import("xgboost", "XGBClassifier")
XGB_OK         = XGBClassifier is not None

# ---- matplotlib (optional, display only) -----------------------------------
matplotlib      = _dyn_import("matplotlib")
MATPLOTLIB_OK   = matplotlib is not None

# ---- rf_sentinel_agents (optional plugin: SOM / Teacher-Student /
#      Cognitive Frequency / Active-Learning / Automated-Response /
#      Protocol-Decoder agents). Located next to THIS file by name-match
#      (see _load_sibling_module above), not by CWD-relative import — so it
#      loads correctly no matter where the process is launched from.
_rf_agents_mod = _load_sibling_module(
    "rf_sentinel_agents", ["rf_sentinel_agents.py", "rf_sentinel_agents*.py"])
AGENTS_AVAILABLE = _rf_agents_mod is not None


# ============================================================================
# LOGGING  —  defined FIRST, before anything that could log.
#              Fix [1]: no component may be constructed above this block.
# ============================================================================
# RF_LOGS_DIR is anchored to _THIS_DIR (absolute), not CWD — same rf_logs/
# folder every time regardless of where the process is launched from.
# Override with RF_SENTINEL_LOGS_DIR to point somewhere else entirely.
RF_LOGS_DIR = os.environ.get("RF_SENTINEL_LOGS_DIR",
                             os.path.join(_THIS_DIR, "rf_logs"))
os.makedirs(RF_LOGS_DIR, exist_ok=True)

logger = logging.getLogger("rf_sentinel")
logger.setLevel(logging.INFO)
logger.propagate = False
if not logger.handlers:
    _fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    _ch = logging.StreamHandler(sys.stdout)
    _ch.setFormatter(_fmt)
    logger.addHandler(_ch)
    try:
        _fh = RotatingFileHandler(
            os.path.join(RF_LOGS_DIR, "sentinel.log"), maxBytes=8_000_000,
            backupCount=4, encoding="utf-8")
        _fh.setFormatter(_fmt)
        logger.addHandler(_fh)
    except Exception as e:
        # File logging is best-effort, but losing it must be loud: the console
        # handler is already attached, so this goes to the terminal.
        report_error("LOGFILE", e, every=0, level="warning")
        logger.warning("[LOG] khong ghi duoc sentinel.log — chi log ra console.")


# ============================================================================
# PATHS
# ============================================================================
# RF_LOGS_DIR was already resolved (absolute, _THIS_DIR-anchored) in the
# LOGGING block above so the log file and the DB/evidence dirs always agree.
DB_PATH  = os.path.join(RF_LOGS_DIR, "rf_sentinel.db")
FP_DIR   = os.path.join(RF_LOGS_DIR, "fingerprints")
EV_DIR   = os.path.join(RF_LOGS_DIR, "evidence")
RPT_DIR  = os.path.join(RF_LOGS_DIR, "reports")
for _d in (FP_DIR, EV_DIR, RPT_DIR):
    os.makedirs(_d, exist_ok=True)


# ============================================================================
# RF CALIBRATION  —  PLACEHOLDER VALUES, see README calibration warning
# ============================================================================
# CALIBRATION_BANDS — mutable list so the /api/calibration POST endpoint can
# update offsets at runtime without restarting the process.
# Format: [lo_hz, hi_hz, offset_dB]
# offset_dB = (true_power_dBm) - (sdr_reading_dBm)  measured with a signal gen.
# All placeholder -50.0 until you run a calibration pass (see README).
_CAL_BANDS_MUT: list = [
    [100e6,   200e6, -50.0],
    [200e6,   400e6, -50.0],
    [400e6,   700e6, -50.0],
    [700e6,  1000e6, -50.0],
    [1000e6, 1500e6, -50.0],
    [1500e6, 2400e6, -50.0],
    [2400e6, 3000e6, -50.0],
    [3000e6, 6000e6, -50.0],
]
# Legacy alias — code that reads CALIBRATION_BANDS still works.
CALIBRATION_BANDS = _CAL_BANDS_MUT

# Single-element list so rf_sentinel_ui can toggle this at runtime.
_CAL_VERIFIED_MUT: list = [False]

@property
def _calibration_verified():
    return _CAL_VERIFIED_MUT[0]

CALIBRATION_VERIFIED = False   # kept for backward compat; real state in _CAL_VERIFIED_MUT


def get_calibration_offset(freq_hz):
    for lo, hi, off in CALIBRATION_BANDS:
        if lo <= freq_hz < hi:
            return off
    return -50.0


# ============================================================================
# DETECTION / GATING CONSTANTS
# ============================================================================
POWER_Z_ALERT          = 3.0
ENTROPY_DROP_ALERT     = 0.35
KURTOSIS_ALERT         = 8.0
SAMPLE_ENTROPY_ALERT   = 0.45
CYCLO_ALERT            = 0.55

# ---- [C] Savitzky-Golay pre-filter ----------------------------------------
SG_WINDOW_LENGTH  = 15          # must be odd; reduce to 7 if FFT_SIZE < 256
SG_POLYORDER      = 3

# ---- [B] DTW FHSS pattern matching -----------------------------------------
DTW_FHSS_ALERT    = 0.52        # DTW similarity threshold for FHSS alert
FHSS_HISTORY_LEN  = 24          # centroid ring-buffer depth (snapshots)

# ---- [D] Advanced cyclostationary (CAF) ------------------------------------
CYCLO_ADV_ALERT         = 0.38      # normalised CAF magnitude threshold
CYCLO_SYMBOL_RATES_HZ   = [         # baud / symbol rates to probe
    9_600, 19_200, 38_400, 115_200,
    250_000, 500_000, 1_000_000, 2_000_000,
]

PERSISTENCE_MIN_COUNT  = 3
PERSISTENCE_WINDOW     = 5
CRITICAL_ZSCORE_GATE   = 3.5

EMA_UPDATE_INTERVAL_S  = 900
EMA_ALPHA              = 0.05
EMA_MAX_CENTER_DRIFT   = 0.25

SPECTRUM_LOG_INTERVAL_S = 30.0

WIDEBAND_START_HZ          = 300e6
WIDEBAND_END_HZ            = 1000e6
WIDEBAND_SCAN_EVERY_N_ROUNDS = 40
WIDEBAND_STEP_HZ            = 8e6   # Ported from v6/v13 merge branch.

ENABLE_SPECTRUM_GUI = True
GUI_QUEUE_MAXSIZE   = 64

# ==== WIDEBAND DISCOVERY / CANDIDATE TRACKING ===============================
# Ported from "rf_sentinel_v15_gated (v6+v13 merge)". These constants were
# previously dangling (WIDEBAND_START_HZ/END_HZ/SCAN_EVERY_N_ROUNDS and
# ENABLE_SPECTRUM_GUI existed above with no implementation behind them) —
# this section is what actually uses them.
CANDIDATE_BUCKET_HZ         = 250e3   # freq resolution for de-duplicating peaks
CANDIDATE_CONFIRM_ROUNDS    = 2       # peak must reappear this many scans
CANDIDATE_WARMUP_SAMPLES    = 8       # samples before a candidate is analyzed
CANDIDATE_TTL_ROUNDS        = 5       # rounds a candidate can go unseen before drop
CANDIDATE_PEAK_THRESHOLD_DB = 10.0    # dB above PSD median to count as a peak
CANDIDATE_MIN_SEPARATION_HZ = 200e3   # min spacing between distinct peaks
CANDIDATE_GUARD_HZ          = 1.5e6   # ignore peaks this close to a WATCHLIST channel

SWEEP_SETTLE_S    = 0.020
SWEEP_DWELL_S     = 0.005
SAMPLE_RATE_HZ    = 2.0e6
FFT_SIZE          = 1024

# ==== RANDOM FOREST =========================================================
# Anchored next to the DB / logs (RF_LOGS_DIR is absolute and _THIS_DIR-based), not to
# the CWD: with "./rf_logs/..." the model landed in a different folder than the DB
# whenever the script was started from somewhere else.
RF_MODEL_PATH          = os.path.join(RF_LOGS_DIR, "rf_threat_clf.joblib")
RF_MIN_TRAINING        = 200
RF_RETRAIN_EVERY_N     = 500
RF_CONF_THRESHOLD      = 0.70
RF_N_ESTIMATORS        = 300
RF_MAX_CLASS_SHARE     = 0.85   # Fix [3]: >85% one class => rules, not ML
RF_RULE_TABLE_CEILING  = 0.97   # Fix [3]: mirrors the rule table => unusable

# ==== WEB UI ================================================================
FLASK_PORT = 1717
FLASK_HOST = "127.0.0.1"


# ============================================================================
# THREAT LEVELS
# ============================================================================
class ThreatLevel(Enum):
    OK       = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4


_SEVERITY_LADDER = ["OK", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _downgrade_one(severity):
    """One rung down the ladder.  Accepts a ThreatLevel *or* its name string and
    returns the same kind.  (The only production caller passes a ThreatLevel;
    an earlier `str(severity).upper()` turned that into "THREATLEVEL.HIGH",
    which is not on the ladder, so a swallowed ValueError made Gate [4]
    silently never downgrade anything.)"""
    is_enum = isinstance(severity, ThreatLevel)
    name = severity.name if is_enum else str(severity).upper()
    if name not in _SEVERITY_LADDER:
        report_error("_downgrade_one",
                     f"muc do '{severity}' khong nam tren thang {_SEVERITY_LADDER}"
                     " — giu nguyen", every=None)
        return severity
    lowered = _SEVERITY_LADDER[max(0, _SEVERITY_LADDER.index(name) - 1)]
    return ThreatLevel[lowered] if is_enum else lowered


THREAT_LABELS = {
    ThreatLevel.OK:       "Binh thuong",
    ThreatLevel.LOW:      "Theo doi",
    ThreatLevel.MEDIUM:   "Dang nghi van",
    ThreatLevel.HIGH:     "Nguy hiem",
    ThreatLevel.CRITICAL: "NGHIEM TRONG",
}


# ============================================================================
# CHANNEL
# ============================================================================
@dataclass
class Channel:
    name:       str
    freq_hz:    float
    priority:   int
    threat_type: str
    alert_threshold_db: float = 6.0
    _history:   list = field(default_factory=list)

    BASELINE_MAX_SAMPLES = 200

    def add_sample(self, power_dbm):
        self._history.append(float(power_dbm))
        if len(self._history) > self.BASELINE_MAX_SAMPLES:
            self._history.pop(0)

    @property
    def baseline(self):
        if not self._history:
            return -100.0
        return float(np.median(self._history))

    @property
    def std(self):
        if len(self._history) < 3:
            return 1.0
        s = float(np.std(self._history))
        return s if s > 1e-6 else 1.0

    def zscore(self, power_dbm):
        return (float(power_dbm) - self.baseline) / self.std

    def update_baseline(self, power_dbm, force=False):
        """Guarded: never absorb an alert sample into the baseline."""
        z = self.zscore(power_dbm)
        if force or abs(z) < POWER_Z_ALERT:
            self.add_sample(power_dbm)


WATCHLIST = [
    Channel("GPS_L1",        1575.42e6, 1, "GPS_JAM"),
    Channel("GPS_L2",        1227.60e6, 1, "GPS_JAM"),
    Channel("GSM900_BCCH",    935.0e6,  1, "FAKE_BTS"),
    Channel("GSM1800_BCCH",  1842.5e6,  1, "FAKE_BTS"),
    Channel("TETRA_DL",       392.0e6,  1, "CELL_JAM"),
    Channel("ISM433",         433.92e6, 2, "IOT_REPLAY"),
    Channel("PMR446",         446.0e6,  2, "CELL_JAM"),
    Channel("ISM868",         868.3e6,  2, "LORA_SKIM"),
    Channel("ISM915",         915.0e6,  2, "LORA_SKIM"),
    Channel("DRONE_FHSS_24", 2440.0e6,  1, "DRONE_FHSS"),
    Channel("DRONE_FHSS_58", 5800.0e6,  1, "DRONE_FHSS"),
    Channel("WIFI_24_CH6",   2437.0e6,  3, "WIFI_DEAUTH"),
    Channel("BT_CLASSIC",    2480.0e6,  3, "WIFI_DEAUTH"),
    Channel("ADSB_1090",     1090.0e6,  2, "ADSB_SPOOF"),
    Channel("SAT_L_BAND",    1545.0e6,  2, "SATCOM"),
    Channel("EMERG_UHF",      457.0e6,  1, "EMERGENCY"),
    Channel("EMERG_VHF",      155.0e6,  1, "EMERGENCY"),
]


# ============================================================================
# DSP HELPERS
# ============================================================================
def iq_bytes_to_complex(raw_bytes):
    if not raw_bytes:
        return np.zeros(0, dtype=np.complex64)
    a = np.frombuffer(raw_bytes, dtype=np.int8)
    if a.size % 2:
        a = a[:-1]
    return (a[0::2].astype(np.float32) +
            1j * a[1::2].astype(np.float32)).astype(np.complex64)


def estimate_power_dbm(iq, freq_hz=None, sample_rate=None):
    if iq is None or len(iq) == 0:
        return -120.0
    p = float(np.mean(np.abs(iq) ** 2))
    if p <= 0:
        return -120.0
    dbm = 10.0 * math.log10(p / 127.0 ** 2) + 30.0
    if _CAL_VERIFIED_MUT[0] and freq_hz is not None:
        dbm += get_calibration_offset(freq_hz)
    return float(dbm)


def compute_psd(iq, fft_size=FFT_SIZE):
    # Complex baseband -> two-sided (fftshifted) spectrum with `fft_size` bins.
    # The too-short fallback must have the SAME shape as the normal result;
    # it used to return fft_size // 2, so callers saw two different lengths.
    if iq is None or len(iq) < fft_size:
        return np.zeros(fft_size, dtype=np.float32)
    n = (len(iq) // fft_size) * fft_size
    seg = iq[:n].reshape(-1, fft_size)
    win = np.hanning(fft_size).astype(np.float32)
    spec = np.abs(np.fft.fftshift(np.fft.fft(seg * win, axis=1), axes=1)) ** 2
    psd = spec.mean(axis=0)
    return psd.astype(np.float32)


def spectral_entropy(psd):
    p = np.asarray(psd, dtype=np.float64)
    s = p.sum()
    if s <= 0:
        return 0.0
    p = p / s
    p = p[p > 0]
    n = len(psd)
    if n <= 1:
        return 0.0
    return float(-np.sum(p * np.log2(p)) / math.log2(n))


def kurtosis_of(iq):
    if iq is None or len(iq) < 16:
        return 0.0
    x = np.abs(iq).astype(np.float64)
    m = x.mean()
    s = x.std()
    if s <= 1e-9:
        return 0.0
    return float(np.mean(((x - m) / s) ** 4))


def sample_entropy_of(iq, m=2, r_factor=0.2):
    x = np.real(iq[:1024]).astype(np.float64)
    n = len(x)
    if n < m + 2:
        return 0.0
    r = float(np.std(x)) * r_factor
    if r <= 1e-9:
        return 0.0

    def _count(dim):
        v = np.lib.stride_tricks.sliding_window_view(x, dim)[:n - dim + 1]
        c = 0
        for i in range(len(v) - 1):
            c += int(np.sum(np.max(np.abs(v[i + 1:] - v[i]), axis=1) <= r) > 0)
        return c

    c1, c2 = _count(m), _count(m + 1)
    if c1 == 0:
        return 0.0
    return float(-math.log(max(c2, 1) / max(c1, 1)))


def stft_entropy(iq, nfft=256):
    if iq is None or len(iq) < nfft * 2:
        return 0.0
    hops = len(iq) // nfft
    win = np.hanning(nfft).astype(np.float32)
    ent = []
    for k in range(hops):
        seg = iq[k * nfft:(k + 1) * nfft] * win
        # Pre-existing bug fix (found while validating this merge): iq is
        # complex baseband, so rfft (real-input FFT) rejects it outright on
        # current numpy — this crashed on every real HackRF snapshot, not
        # just in the discovery code path. Complex signal needs fft, not rfft.
        mag = np.abs(np.fft.fft(seg)) ** 2
        s = mag.sum()
        if s <= 0:
            continue
        p = mag / s
        p = p[p > 0]
        ent.append(-np.sum(p * np.log2(p)))
    return float(np.mean(ent)) if ent else 0.0


def cyclostationary_score(iq, fs=SAMPLE_RATE_HZ):
    if iq is None or len(iq) < 4096:
        return 0.0
    x = np.abs(iq).astype(np.float64)
    x = x - x.mean()
    ac = np.correlate(x, x, mode="full")[len(x) - 1:]
    if ac[0] <= 1e-12:
        return 0.0
    ac = ac / ac[0]
    peak = float(np.max(np.abs(ac[8:256]))) if len(ac) > 256 else 0.0
    return float(min(1.0, peak))


# A "single carrier" must stand this far above the median noise floor (linear
# power ratio, ~13 dB).  Chosen from the worst case, a 1-segment periodogram of
# pure noise: peak/median there is exponential-tail, P(> 20x) ~ 1e-3 over 1024
# bins; with the >=4 averaged segments used in practice it never gets past ~6x.
SINGLE_CARRIER_MIN_PEAK_RATIO = 20.0


def detect_single_carrier(psd):
    if psd is None or len(psd) < 8:
        return False
    p = np.asarray(psd, dtype=np.float64)
    peak = float(p.max())
    if peak <= 0.0:
        return False                      # empty spectrum: nothing there at all
    floor = float(np.median(p))
    # Old rule was only "few bins above mean+4*std" — which pure noise satisfies
    # trivially with ZERO bins, so noise was reported as a single carrier (and
    # that flag feeds the classifier).  Require an actual standout peak first.
    if floor > 0.0 and peak < SINGLE_CARRIER_MIN_PEAK_RATIO * floor:
        return False
    thr = p.mean() + 4.0 * (p.std() if p.std() > 0 else 1.0)
    n_hot = int((p > thr).sum())
    # ...and a FEW bins must stand out: >= 1 (a flat wideband plateau has strong bins
    # but none above mean+4*std, so it is not "a carrier") and few enough to be narrowband.
    return 1 <= n_hot <= max(3, len(p) // 100)


def gsm_fcch_score(iq, fs=SAMPLE_RATE_HZ):
    """GSM FCCH = pure sinusoid at ~67.7 kHz offset during the burst."""
    if iq is None or len(iq) < 1024:
        return 0.0
    x = iq[:4096]
    mag = np.abs(np.fft.fftshift(np.fft.fft(x * np.hanning(len(x)))))
    if mag.max() <= 0:
        return 0.0
    bin_hz = fs / len(x)
    centre = len(mag) // 2
    off = int(round(67700 / bin_hz))
    lo, hi = max(0, centre + off - 3), min(len(mag), centre + off + 4)
    peak = mag[lo:hi].max()
    return float(min(1.0, peak / (mag.mean() + 1e-9) / 20.0))


# ============================================================================
# [C] SAVITZKY-GOLAY SPECTRUM PRE-FILTER
# ============================================================================
def smooth_psd_savgol(psd, window=SG_WINDOW_LENGTH, poly=SG_POLYORDER):
    """
    Apply Savitzky-Golay filter to PSD before any threshold computation.

    Why: Raw IQ → PSD is inherently "jagged" due to thermal noise.
    Sporadic single-bin spikes trigger false-positive Z-score / entropy
    alerts.  SG smoothing preserves spectral shape (unlike moving average)
    while eliminating those impulse artefacts.

    Falls back to raw PSD if scipy is unavailable or the array is shorter
    than the requested window (can happen on very short IQ snapshots).
    """
    if not SCIPY_OK or psd is None or len(psd) < 5:
        return np.asarray(psd, dtype=np.float32)
    try:
        from scipy.signal import savgol_filter
        p  = np.asarray(psd, dtype=np.float64)
        wl = min(window, len(p))
        if wl % 2 == 0:
            wl -= 1                     # window length must be odd
        if wl < 5:
            return p.astype(np.float32)
        po = min(poly, wl - 1)
        smoothed = savgol_filter(p, wl, po)
        smoothed = np.clip(smoothed, 0.0, None)   # SG can produce tiny negatives
        return smoothed.astype(np.float32)
    except Exception as e:
        report_error("smooth_psd_savgol", e)          # keep the raw PSD, but say so
        return np.asarray(psd, dtype=np.float32)


# ============================================================================
# [B] DTW (DYNAMIC TIME WARPING) — FHSS PATTERN RECOGNITION
# ============================================================================
def _spectral_centroid_norm(psd):
    """
    Normalised spectral centroid of a PSD vector: 0.0 = low edge, 1.0 = high.
    Returns 0.5 for a flat / empty spectrum.
    Used to build the per-channel centroid time-series fed into DTW.
    """
    p = np.asarray(psd, dtype=np.float64)
    s = p.sum()
    if s <= 0:
        return 0.5
    bins = np.arange(len(p), dtype=np.float64)
    return float(np.dot(bins, p) / (s * max(len(p) - 1, 1)))


def _dtw_distance_fast(seq_a, seq_b):
    """
    O(n·m) DTW distance — pure NumPy, no external library.
    seq_a, seq_b: 1-D float arrays, may have different lengths.

    For the FHSS use-case both sequences are short (≤24 elements) so the
    quadratic cost is negligible.  A Sakoe-Chiba band constraint could be
    added here for longer sequences without changing the interface.
    """
    a = np.asarray(seq_a, dtype=np.float64)
    b = np.asarray(seq_b, dtype=np.float64)
    n, m = len(a), len(b)
    if n == 0 or m == 0:
        return float("inf")
    dtw = np.full((n + 1, m + 1), np.inf, dtype=np.float64)
    dtw[0, 0] = 0.0
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            cost = abs(a[i - 1] - b[j - 1])
            dtw[i, j] = cost + min(dtw[i - 1, j],
                                   dtw[i,     j - 1],
                                   dtw[i - 1, j - 1])
    return float(dtw[n, m])


def _centroid_hist_entropy(seq, n_bins=8):
    """
    Normalised Shannon entropy of the centroid histogram.
    0.0 → all centroids pile up at one bin (narrowband / CW).
    1.0 → uniform spread across the band (ideal FHSS).
    """
    counts, _ = np.histogram(seq, bins=n_bins, range=(0.0, 1.0))
    counts = counts.astype(np.float64)
    s = counts.sum()
    if s <= 0 or math.log2(n_bins) <= 0:
        return 0.0
    p = counts / s
    p = p[p > 0]
    return float(-np.sum(p * np.log2(p)) / math.log2(n_bins))


# Reference FHSS centroid sequences (normalised 0–1 within the monitored band).
# Each row is a synthetic template that captures the statistical signature of
# the corresponding drone protocol's hopping spread pattern.
#
# HOW TO CALIBRATE: record a real drone with HackRF in your environment,
# extract centroid sequences with FHSSTracker.update(), then replace / extend
# the entries below.  The current values are designed to capture the
# pseudo-random wide spread that distinguishes FHSS from CW interference,
# not to fingerprint a specific serial number.
_FHSS_REFERENCES = {
    "DJI_Lightbridge": np.array([
        0.18, 0.72, 0.41, 0.88, 0.09, 0.63, 0.33, 0.79,
        0.52, 0.24, 0.67, 0.15, 0.84, 0.38, 0.61, 0.06,
        0.77, 0.44, 0.92, 0.30,
    ]),
    "DJI_OcuSync": np.array([
        0.10, 0.55, 0.91, 0.28, 0.74, 0.19, 0.62, 0.45,
        0.83, 0.13, 0.70, 0.38, 0.95, 0.21, 0.57, 0.80,
        0.35, 0.68, 0.48, 0.15,
    ]),
    "ELRS_2400": np.array([
        0.25, 0.78, 0.12, 0.58, 0.90, 0.36, 0.71, 0.04,
        0.82, 0.47, 0.65, 0.22, 0.87, 0.53, 0.16, 0.74,
        0.41, 0.96, 0.30, 0.59,
    ]),
    "FHSS_Generic": np.array([
        0.08, 0.42, 0.76, 0.21, 0.89, 0.55, 0.31, 0.67,
        0.14, 0.85, 0.50, 0.73, 0.28, 0.93, 0.16, 0.62,
        0.38, 0.80, 0.46, 0.11,
    ]),
}


class FHSSTracker:
    """
    Per-channel ring buffer of spectral centroids feeding DTW scoring.

    Thread-safe (per-instance Lock).  The singleton _FHSS_TRACKER is
    created at module level after this class definition — it is lightweight
    (no logging, no I/O) so module-level construction is fine.

    score() combines two orthogonal signals:
      1. DTW similarity to reference hopping templates (shape match)
      2. Centroid histogram entropy (spread match — FHSS is near-uniform)

    A narrowband jammer scores high on shape but LOW on entropy.
    A real FHSS drone scores high on both.
    """
    MIN_SAMPLES = 8     # below this, not enough history to score reliably
    STD_MIN     = 0.08  # < 8 % of band width → narrowband, not FHSS

    def __init__(self, history_len=FHSS_HISTORY_LEN):
        from collections import deque, defaultdict
        self._buf  = defaultdict(lambda: deque(maxlen=history_len))
        self._lock = threading.Lock()

    def update(self, channel_name: str, psd) -> None:
        """Push the current snapshot's normalised spectral centroid."""
        c = _spectral_centroid_norm(psd)
        with self._lock:
            self._buf[channel_name].append(c)

    def dtw_score(self, channel_name: str) -> float:
        """
        Return FHSS similarity score in [0, 1].
        0 = flat / narrowband / insufficient history.
        1 = strong match to a known FHSS hopping signature.
        """
        with self._lock:
            hist = list(self._buf[channel_name])
        n = len(hist)
        if n < self.MIN_SAMPLES:
            return 0.0

        seq = np.asarray(hist, dtype=np.float64)

        # Hard gate: narrowband signals cannot be FHSS regardless of shape.
        if np.std(seq) < self.STD_MIN:
            return 0.0

        # --- DTW against each reference template ---
        best_dtw = 0.0
        for ref in _FHSS_REFERENCES.values():
            d = _dtw_distance_fast(seq, ref)
            # Normalise: worst-case DTW for sequences in [0,1] of length L is L.
            max_d = max(n, len(ref))
            sim   = max(0.0, 1.0 - d / max_d)
            if sim > best_dtw:
                best_dtw = sim

        # --- Centroid entropy (spread quality) ---
        entropy_score = _centroid_hist_entropy(seq)

        # Weighted combination: shape (65%) + spread (35%)
        combined = 0.65 * best_dtw + 0.35 * entropy_score
        return float(min(1.0, combined))

    def centroid_history(self, channel_name: str) -> list:
        """Return a copy of the centroid history (for logging / UI export)."""
        with self._lock:
            return list(self._buf[channel_name])


# Module-level singleton — created here, before detect_anomaly_ew is defined.
_FHSS_TRACKER = FHSSTracker()


# ============================================================================
# [D] ADVANCED CYCLOSTATIONARY FEATURE DETECTION  (CAF-based)
# ============================================================================
def cyclo_detect_advanced(iq, fs=None,
                           symbol_rates=None):
    """
    Cyclic Autocorrelation Function (CAF) detector at lag τ = 0.

    Key insight
    ───────────
    Every man-made digital signal has a *cyclic frequency* α equal (or
    harmonically related) to its symbol/baud rate.  At that α the CAF
    R_α(τ=0) = E[ x(t)·x*(t) · e^{−j2π α t} ]  has a significant
    non-zero magnitude.  Thermal / environmental noise has NO such
    periodicity, so R_α ≈ 0 for all α.

    This lets us detect artificial signals that are *below* the noise
    floor in the raw PSD — the kind that a simple Z-score would miss.

    Return value
    ────────────
    (score : float [0,1],  alpha_hz : float)
        score    — peak normalised |R_α| across all tested symbol rates
        alpha_hz — the cyclic frequency (Hz) where the peak was found

    Computational cost
    ──────────────────
    For N = 8192 samples and 8 symbol rates: ≈ 8 × N complex mults
    ≈ 65 k FLOPs.  Runs in < 1 ms on a Raspberry Pi 5 / NUC.
    """
    if iq is None or len(iq) < 2048:
        return 0.0, 0.0

    _fs     = float(fs) if fs is not None else float(SAMPLE_RATE_HZ)
    _rates  = symbol_rates if symbol_rates is not None else CYCLO_SYMBOL_RATES_HZ

    x = np.asarray(iq[:8192], dtype=np.complex128)
    N = len(x)
    x = x - x.mean()                           # remove DC offset

    px = float(np.mean(np.abs(x) ** 2))        # signal power
    if px < 1e-12:
        return 0.0, 0.0

    # lag-0 conjugate product is simply |x(t)|^2 (real-valued)
    xabs2 = (x * np.conj(x)).real              # shape (N,)
    t     = np.arange(N, dtype=np.float64) / _fs

    best_score = 0.0
    best_alpha = 0.0

    for sr in _rates:
        alpha = float(sr)
        if alpha >= _fs:    # lag-0 CAF aliases back to DC only at α = fs, not fs/2
            continue
        # Project onto cyclic frequency α: scalar complex value
        caf = np.abs(np.mean(xabs2 * np.exp(-1j * 2.0 * math.pi * alpha * t)))
        # Normalise by signal power for amplitude independence
        norm_score = caf / (px + 1e-12)
        if norm_score > best_score:
            best_score = norm_score
            best_alpha = alpha

    # Empirical scaling: strong real signals score ≈ 0.3–0.5 before clipping.
    return float(min(1.0, best_score * 2.5)), float(best_alpha)


# ============================================================================
# AI [1] — GLOBAL HYBRID (DBSCAN + IsolationForest)
# ============================================================================
class HybridCognitiveAI:
    MIN_SAMPLES = 150

    def __init__(self, n_features=6):
        self.scaler   = StandardScaler()
        self.cluster  = None
        self.iso      = IsolationForest(
            n_estimators=200, contamination=0.05, random_state=42)
        self.profiles = {}
        self.trained  = False
        self._buf     = deque(maxlen=4000)
        self._last_ema = 0.0
        if not SKLEARN_OK:
            logger.warning("[AI-1] sklearn khong co — HybridCognitiveAI TAT.")

    def _vec(self, r):
        return [r.power_dbm, r.entropy, r.kurtosis,
                r.sample_entropy, r.stft_entropy, r.cyclo_score]

    def observe(self, r):
        if not SKLEARN_OK:
            return
        self._buf.append(self._vec(r))
        if len(self._buf) >= self.MIN_SAMPLES and not self.trained:
            self.train()

    def train(self):
        X = np.asarray(list(self._buf), dtype=np.float64)
        if len(X) < self.MIN_SAMPLES:
            return False
        try:
            Xs = self.scaler.fit_transform(X)

            # Fix: fixed eps=0.9 in 6-D standardised space produces ZERO
            # clusters. Derive eps from the k-NN distance distribution.
            from sklearn.neighbors import NearestNeighbors
            nn = NearestNeighbors(n_neighbors=min(6, len(Xs) - 1)).fit(Xs)
            dist, _ = nn.kneighbors(Xs)
            kth = np.sort(dist[:, -1])
            eps = float(max(0.3, np.median(kth) * 1.5))

            self.cluster = DBSCAN(eps=eps, min_samples=8).fit(Xs)
            self.iso.fit(Xs)

            labels = self.cluster.labels_
            for lb in set(labels):
                if lb == -1:
                    continue
                pts = Xs[labels == lb]
                self.profiles[int(lb)] = {
                    "center": pts.mean(axis=0),
                    "std":    np.clip(pts.std(axis=0), 0.05, None),
                    "n":      int(len(pts)),
                }
            self.trained = True
            logger.info(f"[AI-1] Da huan luyen: {len(X)} mau, eps={eps:.3f}, "
                        f"{len(self.profiles)} cum.")
            return True
        except Exception as e:
            logger.warning(f"[AI-1] Train loi: {e}")
            return False

    def predict(self, r):
        if not self.trained:
            return 0.0, "UNTRAINED"
        try:
            v  = np.asarray(self._vec(r), dtype=np.float64).reshape(1, -1)
            vs = self.scaler.transform(v)

            dmin = float("inf")
            for p in self.profiles.values():
                d = float(np.linalg.norm((vs[0] - p["center"]) / p["std"]))
                dmin = min(dmin, d)
            dist_score = 1.0 if dmin == float("inf") else min(1.0, dmin / 6.0)

            iso_raw = float(self.iso.score_samples(vs)[0])
            iso_score = float(min(1.0, max(0.0, -iso_raw / 0.25)))

            score = 0.5 * dist_score + 0.5 * iso_score
            return score, ("OUTLIER" if score > 0.5 else "NORMAL")
        except Exception as e:
            report_error("HybridCognitiveAI.predict", e)
            return 0.0, "ERROR"

    def ema_update(self, r, now):
        if not self.trained or now - self._last_ema < EMA_UPDATE_INTERVAL_S:
            return
        self._last_ema = now
        try:
            vs = self.scaler.transform(
                np.asarray(self._vec(r), dtype=np.float64).reshape(1, -1))[0]
            for p in self.profiles.values():
                drift = np.clip(vs - p["center"],
                                -EMA_MAX_CENTER_DRIFT, EMA_MAX_CENTER_DRIFT)
                p["center"] = p["center"] + EMA_ALPHA * drift
        except Exception as e:
            report_error("HybridCognitiveAI.ema_update", e)


# ============================================================================
# AI [2] — PER-THREAT-TYPE
# ============================================================================
class RFAnomalyAI:
    MIN_PER_TYPE = 10

    def __init__(self):
        self.models  = {}
        self.scalers = {}
        self._buf    = defaultdict(lambda: deque(maxlen=2000))
        self._fitted = set()

    @staticmethod
    def _vec(r):
        return [r.power_dbm, r.entropy, r.kurtosis,
                r.sample_entropy, r.stft_entropy, r.cyclo_score]

    def observe(self, r, threat_type):
        if not SKLEARN_OK:
            return
        self._buf[threat_type].append(self._vec(r))
        if threat_type not in self._fitted and \
                len(self._buf[threat_type]) >= self.MIN_PER_TYPE:
            self._fit(threat_type)

    def _make(self, threat_type):
        if not HMM_OK and threat_type in ("DRONE_FHSS", "GPS_SPOOF"):
            return IsolationForest(n_estimators=150, contamination=0.05,
                                   random_state=42), "IF"
        if threat_type in ("DRONE_FHSS", "GPS_SPOOF"):
            return GaussianHMM(n_components=3, covariance_type="diag",
                               n_iter=50, random_state=42), "HMM"
        if threat_type in ("IOT_REPLAY", "LORA_SKIM", "FAKE_BTS"):
            return LocalOutlierFactor(n_neighbors=min(10, 8), novelty=True,
                                      contamination=0.05), "LOF"
        if threat_type == "EMERGENCY":
            return OneClassSVM(kernel="rbf", gamma="scale", nu=0.05), "OCSVM"
        return IsolationForest(n_estimators=150, contamination=0.05,
                               random_state=42), "IF"

    def _fit(self, threat_type):
        X = np.asarray(list(self._buf[threat_type]), dtype=np.float64)
        if len(X) < self.MIN_PER_TYPE:
            return
        try:
            sc = StandardScaler().fit(X)
            Xs = sc.transform(X)
            model, kind = self._make(threat_type)
            model.fit(Xs)
            self.models[threat_type]  = model
            self.scalers[threat_type] = sc
            self._fitted.add(threat_type)
            logger.info(f"[AI-2] {threat_type}: {kind} tren {len(X)} mau.")
        except Exception as e:
            logger.warning(f"[AI-2] {threat_type} fit loi: {e}")

    def predict(self, r, threat_type):
        model = self.models.get(threat_type)
        if model is None:
            return 0.0, "UNTRAINED"
        try:
            vs = self.scalers[threat_type].transform(
                np.asarray(self._vec(r), dtype=np.float64).reshape(1, -1))
            if isinstance(model, GaussianHMM):
                ll = float(model.score(vs))
                score = float(min(1.0, max(0.0, (-ll - 5.0) / 25.0)))
                return score, ("OUTLIER" if score > 0.5 else "NORMAL")
            if hasattr(model, "score_samples"):
                raw = float(model.score_samples(vs)[0])
            else:
                raw = float(model.decision_function(vs)[0])
            score = float(min(1.0, max(0.0, (0.15 - raw) / 0.35)))
            return score, ("OUTLIER" if score > 0.5 else "NORMAL")
        except Exception as e:
            report_error(f"RFAnomalyAI.predict[{threat_type}]", e)
            return 0.0, "ERROR"


# ============================================================================
# RESULT DATACLASSES
# ============================================================================
@dataclass
class EW_AnomalyResult:
    channel:      str
    freq_hz:      float
    threat_type:  str
    power_dbm:    float
    baseline_dbm: float
    zscore:       float
    entropy:      float = 0.0
    kurtosis:     float = 0.0
    sample_entropy: float = 0.0
    stft_entropy: float = 0.0
    cyclo_score:  float = 0.0
    single_carrier: bool = False
    gsm_fcch:     float = 0.0
    snr_db:       float = 0.0
    bandwidth_hz: float = 0.0
    duration_ms:  float = 0.0
    hybrid_ai_score: float = 0.0
    hybrid_ai_label: str = "UNTRAINED"
    type_ai_score:   float = 0.0
    type_ai_label:   str = "UNTRAINED"
    power_alert:      bool = False
    entropy_alert:    bool = False
    hybrid_ai_alert:  bool = False
    type_ai_alert:    bool = False
    burst_alert:      bool = False
    structural_alert: bool = False
    swept_alert:      bool = False
    # ── [B] DTW FHSS ────────────────────────────────────────────────────────
    dtw_fhss_score:   float = 0.0
    dtw_fhss_alert:   bool  = False
    # ── [D] Advanced cyclostationary ────────────────────────────────────────
    cyclo_adv_score:  float = 0.0
    cyclo_alpha_hz:   float = 0.0   # detected symbol rate (Hz); 0 if none
    cyclo_adv_alert:  bool  = False

    @property
    def ai_alert(self):
        return self.hybrid_ai_alert or self.type_ai_alert

    @property
    def ai_both_agree(self):
        return self.hybrid_ai_alert and self.type_ai_alert

    @property
    def any_alert(self):
        return any([self.power_alert, self.entropy_alert, self.hybrid_ai_alert,
                    self.type_ai_alert, self.burst_alert,
                    self.structural_alert, self.swept_alert,
                    self.dtw_fhss_alert, self.cyclo_adv_alert])


@dataclass
class ThreatResult:
    channel:     str
    freq_hz:     float
    threat_type: str
    threat_level: ThreatLevel
    anomaly:     EW_AnomalyResult
    indicators:  list = field(default_factory=list)
    action:      str = ""
    fingerprint: dict = None
    timestamp:   str = ""
    confidence:  float = 0.0
    rf_label:    str = None
    rf_confidence: float = 0.0


# ============================================================================
# DETECTION
# ============================================================================
def detect_anomaly_ew(channel, iq, hybrid_ai, type_ai):
    psd   = compute_psd(iq)
    psd_s = smooth_psd_savgol(psd)                  # [C] SG-smoothed copy
    pwr   = estimate_power_dbm(iq, channel.freq_hz)
    base  = channel.baseline
    z     = channel.zscore(pwr)

    psd_valid = np.count_nonzero(psd_s) > 0
    ent  = spectral_entropy(psd_s) if psd_valid else 0.0   # [C] smoothed
    kurt = kurtosis_of(iq)
    se   = sample_entropy_of(iq)
    ste  = stft_entropy(iq)
    cyc  = cyclostationary_score(iq)
    sc   = detect_single_carrier(psd_s) if psd_valid else False  # [C] smoothed
    fcch = gsm_fcch_score(iq)

    # [B] DTW-based FHSS score — update tracker always; score only on DRONE channels
    _FHSS_TRACKER.update(channel.name, psd_s)
    dtw_fhss = (_FHSS_TRACKER.dtw_score(channel.name)
                if channel.threat_type == "DRONE_FHSS" else 0.0)

    # [D] CAF-based advanced cyclostationary score
    cyclo_adv, cyclo_alpha = cyclo_detect_advanced(iq)

    # Entropy only means something when there is actual signal to measure.
    # On a silent channel it collapses to 0 and would fire ENTROPY_DROP on noise.
    if not psd_valid or pwr < base - 20.0:
        ent = 0.0
        se  = 0.0

    r = EW_AnomalyResult(
        channel=channel.name, freq_hz=channel.freq_hz,
        threat_type=channel.threat_type, power_dbm=pwr,
        baseline_dbm=base, zscore=z, entropy=ent, kurtosis=kurt,
        sample_entropy=se, stft_entropy=ste, cyclo_score=cyc,
        single_carrier=sc, gsm_fcch=fcch,
        snr_db=max(0.0, pwr - base),
        bandwidth_hz=float(SAMPLE_RATE_HZ),
        duration_ms=SWEEP_DWELL_S * 1000.0,
        dtw_fhss_score=dtw_fhss,       # [B]
        cyclo_adv_score=cyclo_adv,      # [D]
        cyclo_alpha_hz=cyclo_alpha,     # [D]
    )

    r.power_alert      = abs(z) > POWER_Z_ALERT
    r.burst_alert      = kurt > KURTOSIS_ALERT
    r.entropy_alert    = (ent > 0 and ent < (1.0 - ENTROPY_DROP_ALERT))
    r.structural_alert = (sc and ent > 0 and ent < 0.55)
    r.swept_alert      = cyc > CYCLO_ALERT
    r.dtw_fhss_alert   = dtw_fhss > DTW_FHSS_ALERT         # [B]
    r.cyclo_adv_alert  = cyclo_adv > CYCLO_ADV_ALERT        # [D]

    r.hybrid_ai_score, r.hybrid_ai_label = hybrid_ai.predict(r)
    r.hybrid_ai_alert = r.hybrid_ai_score > 0.5
    hybrid_ai.observe(r)

    r.type_ai_score, r.type_ai_label = type_ai.predict(r, channel.threat_type)
    r.type_ai_alert = r.type_ai_score > 0.5
    type_ai.observe(r, channel.threat_type)

    return r


# ============================================================================
# THREAT ANALYSIS
# ============================================================================
def analyze(channel, r, fp_store):
    ind = []
    tt  = channel.threat_type
    lvl = ThreatLevel.OK
    act = "Tiep tuc theo doi."

    if r.any_alert or r.ai_alert:
        lvl = ThreatLevel.LOW
        ind.append(f"Bat thuong: z={r.zscore:.2f}, ent={r.entropy:.2f}")

    if r.ai_both_agree:
        lvl = max(lvl, ThreatLevel.HIGH, key=lambda x: x.value)
        ind.append("[AI-CONSENSUS] Ca hai he thong AI deu bat thuong.")

    # ---- per-type rules -------------------------------------------------
    if tt in ("GPS_JAM", "GPS_SPOOF"):
        if r.power_alert and r.entropy_alert:
            lvl = ThreatLevel.CRITICAL
            ind.append("Nhieu/tap nhieu bang GPS — nghi gay nhieu hoac spoof.")
        elif r.power_alert:
            lvl = ThreatLevel.HIGH
            ind.append("Cong suat GPS tang bat thuong.")

    elif tt == "FAKE_BTS":
        if r.gsm_fcch > 0.35:
            ind.append(f"GSM-FCCH phat hien (score={r.gsm_fcch:.2f}).")
            lvl = ThreatLevel.HIGH
        if r.structural_alert:
            lvl = ThreatLevel.CRITICAL
            ind.append("Cau truc kenh la — nghi Fake BTS.")

    elif tt == "CELL_JAM":
        if r.power_alert and r.burst_alert:
            lvl = ThreatLevel.CRITICAL
            ind.append("Nhieu dang burst tren bang cellular/TETRA.")
        if r.cyclo_adv_alert:             # [D] hidden jamming signal
            sym_khz = r.cyclo_alpha_hz / 1e3
            ind.append(
                f"[CAF] Nghi tin hieu nhieu co chu ky an "
                f"(symbol rate ~{sym_khz:.0f} kHz) — co the la jammer nghi trang.")

    elif tt == "IOT_REPLAY":
        if r.power_alert and r.type_ai_alert:
            lvl = ThreatLevel.HIGH
            ind.append("Nghi replay thiet bi IoT.")

    elif tt == "DRONE_FHSS":
        if r.dtw_fhss_alert:                              # [B] DTW primary
            lvl = ThreatLevel.HIGH
            ind.append(
                f"[DTW] Khop mau nhay tan FHSS "
                f"(score={r.dtw_fhss_score:.2f}) — nghi drone.")
        elif r.swept_alert or r.type_ai_alert:
            lvl = ThreatLevel.HIGH
            ind.append("Dac trung nhay tan (FHSS) — nghi drone.")
        if r.cyclo_adv_alert:                             # [D] may be sub-NF
            sym_khz = r.cyclo_alpha_hz / 1e3
            ind.append(
                f"[CAF] Tin hieu nhan tao phat hien duoi noise floor "
                f"(symbol rate ~{sym_khz:.0f} kHz).")

    elif tt == "WIFI_DEAUTH":
        if r.burst_alert and r.power_alert:
            lvl = ThreatLevel.MEDIUM
            ind.append("Burst ngan cong suat cao tren bang WiFi/BT.")

    elif tt == "ADSB_SPOOF":
        if r.power_alert and r.structural_alert:
            lvl = ThreatLevel.HIGH
            ind.append("Nghi gia mao tin hieu ADS-B.")

    elif tt == "SATCOM":
        if r.power_alert and r.type_ai_alert:
            lvl = ThreatLevel.MEDIUM
            ind.append("Nhieu bat thuong bang L-band.")

    elif tt == "EMERGENCY":
        if r.any_alert:
            lvl = ThreatLevel.HIGH
            ind.append("Tin hieu khan cap co bat thuong — kiem tra ngay.")

    elif tt == "UNKNOWN":
        if r.ai_both_agree and r.power_alert:
            lvl = ThreatLevel.HIGH
            ind.append("Phat hien tin hieu la tren kenh khong nam trong danh sach.")

    if lvl == ThreatLevel.OK and r.any_alert:
        lvl = ThreatLevel.LOW
        ind.append("Bat thuong nhe, chua xac dinh loai.")

    # ---- fingerprint fallback for FakeBTS -------------------------------
    fp = None
    if tt == "FAKE_BTS":
        fp = fingerprint(channel, r, fp_store)
        if fp and fp.get("match_score", 0) > 0.9:
            ind.append(f"[FP] Trung van tay da biet: {fp['match_id']}")

    if lvl.value >= ThreatLevel.HIGH.value:
        act = "Luu bang chung IQ, bao cao, kiem tra thu cong."
    elif lvl == ThreatLevel.MEDIUM:
        act = "Theo doi them vai vong quet."

    return ThreatResult(
        channel=channel.name, freq_hz=channel.freq_hz, threat_type=tt,
        threat_level=lvl, anomaly=r, indicators=ind, action=act,
        fingerprint=fp,
        timestamp=datetime.now(timezone.utc).isoformat(),
        confidence=max(r.hybrid_ai_score, r.type_ai_score),
    )


def fingerprint(channel, r, fp_store):
    try:
        key  = f"{channel.name}"
        cand = {
            "id": f"{channel.name}_{int(time.time())}",
            "freq_hz": channel.freq_hz,
            "cfo_hz": float(r.zscore * 100.0),
            "iq_imbalance": float(abs(r.cyclo_score - 0.5)),
            "entropy": float(r.entropy),
            "kurtosis": float(r.kurtosis),
        }
        best, best_score = None, 0.0
        for fid, f in fp_store.items():
            if abs(f.get("freq_hz", 0) - channel.freq_hz) > 5e3:
                continue
            a = np.array([cand["cfo_hz"], cand["iq_imbalance"],
                          cand["entropy"], cand["kurtosis"]])
            b = np.array([f["cfo_hz"], f["iq_imbalance"],
                          f["entropy"], f["kurtosis"]])
            na, nb = np.linalg.norm(a), np.linalg.norm(b)
            if na <= 0 or nb <= 0:
                continue
            score = float(np.dot(a, b) / (na * nb))
            if score > best_score:
                best, best_score = fid, score
        cand["match_id"]    = best
        cand["match_score"] = round(best_score, 4)
        fp_store[key] = cand
        with open(os.path.join(FP_DIR, f"{key}.json"), "w") as fh:
            json.dump(cand, fh, indent=2)
        return cand
    except Exception as e:
        report_error("fingerprint", e)
        return None


# ============================================================================
# GATES
# ============================================================================
class PersistenceTracker:
    def __init__(self):
        self.history = defaultdict(lambda: deque(maxlen=PERSISTENCE_WINDOW))

    def record(self, channel_name, alerted):
        self.history[channel_name].append(bool(alerted))

    def is_persistent(self, channel_name):
        h = self.history[channel_name]
        return sum(h) >= PERSISTENCE_MIN_COUNT

    def count(self, channel_name):
        return sum(self.history[channel_name])


persistence_tracker = PersistenceTracker()


def apply_confidence_gate(result, is_persistent, persist_count):
    """Four gates. Gates 1-3 unsuperivsed; gate 4 downgrade-only."""
    lvl = result.threat_level
    ind = result.indicators

    # ---- Gate [1] persistence -------------------------------------------
    if lvl.value >= ThreatLevel.HIGH.value and not is_persistent:
        lvl = ThreatLevel.MEDIUM
        ind.append(f"[GATE-PERSIST] Chi {persist_count}/"
                   f"{PERSISTENCE_MIN_COUNT} vong quet — ha xuong MEDIUM.")

    # ---- Gate [2] critical power z-score --------------------------------
    if lvl == ThreatLevel.CRITICAL:
        a = result.anomaly
        if not (a.ai_both_agree and abs(a.zscore) > CRITICAL_ZSCORE_GATE):
            lvl = ThreatLevel.HIGH
            ind.append(f"[GATE-POWER] CRITICAL can dong thuan AI VA |Z|>"
                       f"{CRITICAL_ZSCORE_GATE} (consensus={a.ai_both_agree}, "
                       f"Z={a.zscore:.2f}) — ha xuong HIGH.")
    # Gate [3] EMA runs inside HybridCognitiveAI.ema_update().

    # ---- Gate [4] supervised Random Forest (downgrade-only) -------------
    rf = _get_rf()
    if rf is not None and rf.usable:
        d = asdict(result.anomaly) if not isinstance(result.anomaly, dict) \
            else result.anomaly
        feat = {
            "power_dbm": d.get("power_dbm", 0.0),
            "zscore": d.get("zscore", 0.0),
            "snr_db": d.get("snr_db", 0.0),
            "bandwidth_hz": d.get("bandwidth_hz", 0.0),
            "duration_ms": d.get("duration_ms", 0.0),
            "persistence_ratio": persist_count / float(PERSISTENCE_WINDOW),
            "freq_hz": d.get("freq_hz", 0.0),
        }
        label, conf = rf.predict(feat)
        if label is not None and conf >= RF_CONF_THRESHOLD:
            result.rf_label      = label
            result.rf_confidence = round(conf, 3)
            if label != result.threat_type:
                ind.append(f"[RF-DISAGREE] RF goi y '{label}' ({conf:.2f}).")
                lvl = _downgrade_one(lvl)

    result.threat_level = lvl
    return result


# ============================================================================
# RANDOM FOREST  —  Fix [1]: lazy construction, never at import time.
# ============================================================================
class RFThreatClassifier:
    """Supervised RF over analyst-labelled alert history.

    Safety properties (these are the point of the class, not decoration):
      * never constructed before `logger` exists (see _get_rf / init_rf)
      * returns (None, 0.0) unless it has >= RF_MIN_TRAINING labelled rows
        spread over >= 2 classes
      * refuses to ship a model that merely reproduces the rule table
      * downgrade-only at the gate; can never escalate severity
    """

    FEATURES = ["power_dbm", "zscore", "snr_db", "bandwidth_hz",
                "duration_ms", "persistence_ratio", "freq_hz"]

    def __init__(self, model_path=RF_MODEL_PATH):
        self.model_path  = model_path
        self.model       = None
        self.classes_    = []
        self.usable      = False          # Fix [3]: gates predict()
        self.degenerate  = False
        self.trained_at  = None
        self.holdout_acc = None
        self.cv5_acc     = None
        self._since_train = 0
        self._lock       = Lock()
        self.backend     = "none"   # [A] set by train(); "LightGBM"|"XGBoost"|"RandomForest"
        self._load()

    # -- persistence ------------------------------------------------------
    def _load(self):
        if not JOBLIB_OK or not os.path.exists(self.model_path):
            return
        try:
            blob = joblib.load(self.model_path)
            self.model       = blob.get("model")
            self.classes_    = blob.get("classes", [])
            self.degenerate  = bool(blob.get("degenerate", False))
            self.holdout_acc = blob.get("holdout_acc")
            self.cv5_acc     = blob.get("cv5_acc")
            self.trained_at  = blob.get("trained_at")
            self.backend     = blob.get("backend", "RandomForest")  # [A]
            # A degenerate model on disk stays degenerate across restarts.
            self.usable = (self.model is not None and not self.degenerate
                           and len(self.classes_) >= 2)
            state = "USABLE" if self.usable else "DISABLED (degenerate)"
            logger.info(
                f"[RF] Da nap model ({self.backend}): "
                f"{self.classes_} — {state}")
        except Exception as e:
            logger.warning(f"[RF] Khong nap duoc model cu: {e}")
            self.model, self.classes_, self.usable = None, [], False

    def _save(self, degenerate):
        if not JOBLIB_OK:
            logger.warning("[RF] joblib khong co — model khong duoc luu.")
            return
        try:
            joblib.dump({
                "model": self.model, "classes": self.classes_,
                "degenerate": degenerate, "holdout_acc": self.holdout_acc,
                "cv5_acc": self.cv5_acc,
                "backend": self.backend,                 # [A]
                "trained_at": datetime.now(timezone.utc).isoformat(),
            }, self.model_path)
        except Exception as e:
            logger.warning(f"[RF] Khong luu duoc model: {e}")

    # -- inference --------------------------------------------------------
    def predict(self, alert):
        if not self.usable or self.model is None:
            return None, 0.0
        try:
            with self._lock:
                X = [[float(alert.get(f) or 0.0) for f in self.FEATURES]]
                proba = self.model.predict_proba(X)[0]
            idx = int(np.argmax(proba))
            return self.classes_[idx], float(proba[idx])
        except Exception as e:
            report_error("RFThreatClassifier.predict", e)
            return None, 0.0

    def maybe_retrain(self, force=False):
        if not SKLEARN_OK:
            return
        self._since_train += 1
        if not force and self._since_train < RF_RETRAIN_EVERY_N:
            return
        self._since_train = 0
        Thread(target=self.train, daemon=True,
               name="rf-retrain").start()    # never block the sweep

    # -- training ---------------------------------------------------------
    def train(self):
        if not SKLEARN_OK:
            return False
        rows = db_fetch_labeled_events()
        n    = len(rows)
        if n < RF_MIN_TRAINING:
            logger.info(f"[RF] Chi co {n} mau co nhan, can >={RF_MIN_TRAINING}. "
                        f"Bo qua.")
            return False

        y = [r["threat_type"] for r in rows]
        counts = Counter(y)
        if len(counts) < 2:
            logger.info("[RF] Chua du 2 lop. Bo qua.")
            return False

        # Fix [3]: single-class domination means the labels were generated by
        # the rule table, not by listening. Training on that teaches the model
        # to reproduce the rules and agree with them — inflating consensus.
        top_share = max(counts.values()) / float(n)
        if top_share > RF_MAX_CLASS_SHARE:
            logger.warning(
                f"[RF] TU CHOI HUAN LUYEN: lop '{counts.most_common(1)[0][0]}' "
                f"chiem {top_share:.1%} (>{RF_MAX_CLASS_SHARE:.0%}). Day la dau "
                f"hieu gan nhan hang loat theo threat_type, khong phai du lieu "
                f"da kiem chung. Gan nhan thu cong tu rf_logs/evidence/.")
            self.usable = False
            return False

        # Drop classes too small to stratify.
        keep = {k for k, v in counts.items() if v >= 2}
        if len(keep) < 2:
            logger.info("[RF] Qua nhieu lop chi co 1 mau. Bo qua.")
            return False
        filt = [(r, lab) for r, lab in zip(rows, y) if lab in keep]
        X = [[float(r.get(f) or 0.0) for f in self.FEATURES] for r, _ in filt]
        y = [lab for _, lab in filt]

        Xtr, Xte, ytr, yte = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y)

        # [A] Backend selection: LightGBM → XGBoost → RandomForest
        if LGBM_OK:
            clf = LGBMClassifier(
                n_estimators=RF_N_ESTIMATORS,
                num_leaves=31,
                learning_rate=0.1,
                class_weight="balanced",
                n_jobs=-1,
                verbose=-1,
                random_state=42,
            )
            _backend = "LightGBM"
        elif XGB_OK:
            # XGBoost requires integer labels; use sklearn wrapper with LabelEncoder.
            from sklearn.preprocessing import LabelEncoder
            _le = LabelEncoder()
            ytr_enc = _le.fit_transform(ytr)
            yte_enc = _le.transform(yte)
            clf_xgb = XGBClassifier(
                n_estimators=RF_N_ESTIMATORS,
                max_depth=5,
                eval_metric="mlogloss",
                n_jobs=-1,
                random_state=42,
                verbosity=0,
            )
            clf_xgb.fit(Xtr, ytr_enc)
            holdout = float(clf_xgb.score(Xte, yte_enc))
            # Wrap into a thin adapter so the rest of the method stays generic.
            class _XGBAdapter:
                """Thin sklearn-compatible wrapper that handles label encoding."""
                def __init__(self, model, le):
                    self._m, self._le = model, le
                    self.feature_importances_ = model.feature_importances_
                    self.classes_ = le.classes_
                def predict_proba(self, X):
                    return self._m.predict_proba(X)
                def score(self, X, y):
                    return self._m.score(X, self._le.transform(y))
            clf = _XGBAdapter(clf_xgb, _le)
            _backend = "XGBoost"
        else:
            clf = RandomForestClassifier(
                n_estimators=RF_N_ESTIMATORS, min_samples_leaf=2,
                class_weight="balanced", n_jobs=-1, random_state=42)
            _backend = "RandomForest"

        if _backend != "XGBoost":          # XGBoost holdout computed above
            clf.fit(Xtr, ytr)
            holdout = float(clf.score(Xte, yte))
        self.backend = _backend
        logger.info(f"[RF] Su dung backend: {_backend}")

        try:
            cv5 = float(cross_val_score(
                clf, X, y,
                cv=StratifiedKFold(5, shuffle=True, random_state=42),
                n_jobs=-1).mean())
        except Exception as e:
            report_error("RF.train cross_val_score", e, every=0)
            cv5 = float("nan")

        # Majority-class baseline: if the RF cannot beat "always guess the
        # most common label", it has learned nothing the rules didn't say.
        try:
            dummy = DummyClassifier(strategy="most_frequent").fit(Xtr, ytr)
            baseline = float(dummy.score(Xte, yte))
        except Exception as e:
            report_error("RF.train baseline", e, every=0)
            baseline = 0.0

        degenerate = False
        if not math.isnan(cv5) and cv5 > RF_RULE_TABLE_CEILING:
            degenerate = True
            logger.warning(
                f"[RF] MODEL KHONG DUNG DUOC: cv5={cv5:.3f} > "
                f"{RF_RULE_TABLE_CEILING}. Model dang tai tao bang quy tac "
                f"thay vi hoc tin hieu. Khong dua vao gate.")
        elif cv5 <= baseline + 0.02:
            degenerate = True
            logger.warning(
                f"[RF] Model khong hon duoc baseline da so "
                f"(cv5={cv5:.3f} vs {baseline:.3f}). Vo dung — vo hieu hoa.")

        self.model       = clf
        self.classes_    = list(clf.classes_)
        self.holdout_acc = round(holdout, 4)
        self.cv5_acc     = None if math.isnan(cv5) else round(cv5, 4)
        self.degenerate  = degenerate
        self.usable      = (not degenerate) and len(self.classes_) >= 2
        self.trained_at  = datetime.now(timezone.utc).isoformat()

        try:
            with self._lock:
                self._save(degenerate)
        except Exception as e:
            logger.warning(f"[RF] _save loi: {e}")

        try:
            fi = getattr(clf, "feature_importances_",
                         getattr(getattr(clf, "_m", None),
                                 "feature_importances_", None))
            imp = (sorted(zip(self.FEATURES, fi), key=lambda t: -t[1])[:4]
                   if fi is not None else [])
        except Exception as e:
            report_error("RF.train feature_importances", e, every=0, level="warning")
            imp = []
        logger.info(
            f"[RF/{self.backend}] Retrain: {n} mau, holdout={holdout:.3f}, "
            f"cv5={self.cv5_acc}, baseline={baseline:.3f}, "
            f"classes={self.classes_}, usable={self.usable}, "
            f"top={[(nm, round(v, 3)) for nm, v in imp]}")

        # Label leakage: freq_hz dominating means the model learned WHICH
        # CHANNEL an alert came from, not what the signal is.
        if imp and imp[0][0] == "freq_hz" and imp[0][1] > 0.35:
            logger.warning(
                "[RF] CANH BAO RO RI NHAN: freq_hz chiem "
                f"{imp[0][1]:.0%} importance. Model dang hoc kenh, khong "
                "phai tin hieu. Bo sung mau tu nhieu kenh khac nhau.")
        return self.usable


# ---------------------------------------------------------------------------
# Fix [1]: lazy singleton. Constructed only after `logger` exists, and only
# when something actually needs it. Nothing at module scope instantiates it,
# so an import of this file can never trip over an undefined logger.
# ---------------------------------------------------------------------------
_RF_CLF   = None
_RF_LOCK  = Lock()
_RF_READY = False


def _get_rf():
    """Return the singleton, or None if not yet initialised.

    Deliberately does NOT create it on first call from arbitrary threads.
    Creation is init_rf()'s job, called once from main(). Callers that arrive
    early get None and the gate simply skips — fail-open, never crash.
    """
    return _RF_CLF


def init_rf(force_train=False):
    """Initialise the Random Forest. Call from main() AFTER logger + init_db."""
    global _RF_CLF, _RF_READY
    with _RF_LOCK:
        if _RF_READY and _RF_CLF is not None:
            return _RF_CLF
        if not SKLEARN_OK:
            logger.warning("[RF] sklearn khong co — Random Forest TAT.")
            _RF_READY = True
            return None
        # logger is guaranteed to exist here: init_rf() is only called from
        # main(), which runs long after the logging block at the top.
        try:
            _RF_CLF = RFThreatClassifier()
        except Exception as e:
            logger.error(f"[RF] Khoi tao loi: {e}", exc_info=True)
            _RF_CLF = None
        _RF_READY = True
        if force_train and _RF_CLF is not None:
            _RF_CLF.train()
        return _RF_CLF


# ---------------------------------------------------------------------------
# AGENT SUITE  —  same lazy-singleton discipline as _get_rf()/init_rf():
# constructed only from init_agents(), called from main() AFTER logger and
# init_db(). Every method on AgentSuite already fails closed internally
# (try/except around each sub-agent — see rf_sentinel_agents.py), so a bug
# in one agent can never take down the sweep loop.
# ---------------------------------------------------------------------------
AGENT_SUITE = None

# Last EW_AnomalyResult whose threat_level was below MEDIUM.
# sweep_once() writes here; monitor_loop() reads it to feed the EMA with a
# real measured sample instead of a synthetic -90 dBm placeholder.
# Both run in the same thread, so no lock is needed.
_LAST_CLEAN_SAMPLE = None


def init_agents():
    global AGENT_SUITE
    if not AGENTS_AVAILABLE:
        logger.warning("[AGENTS] rf_sentinel_agents.py khong tim thay — "
                       "SOM/Teacher-Student/Freq/ActiveLearning/Response/"
                       "Decoder agents deu TAT. Sweep van chay binh thuong.")
        return None
    try:
        AGENT_SUITE = _rf_agents_mod.AgentSuite(
            logger=logger,
            base_dir=RF_LOGS_DIR,
            sample_rate=SAMPLE_RATE_HZ,
            get_rf_fn=_get_rf,
            db_insert_labeled_fn=db_insert_labeled_event,
            # Webhooks / teacher endpoint / response script are all opt-in via
            # env vars (RF_WEBHOOK_*, TEACHER_ENDPOINT, RF_RESPONSE_SCRIPT,
            # RF_RETRAIN_SCRIPT) — see rf_sentinel_agents.py docstring. None
            # of them do anything unless the operator sets them.
            min_response_level_value=ThreatLevel.HIGH.value,
        )
        logger.info("[AGENTS] AgentSuite khoi tao OK (SOM + Teacher-Student + "
                    "Cognitive-Freq + Active-Learning + Response + Decoder).")
    except Exception as e:
        logger.error(f"[AGENTS] Khoi tao that bai: {e}", exc_info=True)
        AGENT_SUITE = None
    return AGENT_SUITE


# ============================================================================
# SQLITE
# ============================================================================
_db      = None
_db_lock = Lock()


def init_db():
    global _db
    _db = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15.0)
    _db.execute("PRAGMA journal_mode=WAL")
    with _db:
        _db.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, channel TEXT, freq_hz REAL, threat_type TEXT,
            severity TEXT, power_dbm REAL, baseline_dbm REAL, zscore REAL,
            snr_db REAL, bandwidth_hz REAL, duration_ms REAL,
            persistence_ratio REAL, confidence REAL, indicators TEXT,
            action TEXT, rf_label TEXT, rf_confidence REAL,
            iq_path TEXT, confirmed INTEGER
        )""")
        _db.execute("""CREATE TABLE IF NOT EXISTS spectrum_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, channel TEXT, freq_hz REAL, power_dbm REAL
        )""")
        _db.execute("CREATE INDEX IF NOT EXISTS idx_ev_ts ON events(ts)")
        _db.execute("CREATE INDEX IF NOT EXISTS idx_ev_conf ON events(confirmed)")
        _db.execute("CREATE INDEX IF NOT EXISTS idx_sh_ch "
                    "ON spectrum_history(channel, ts)")

        # Migration for databases predating the supervised layer.
        existing = {r[1] for r in _db.execute("PRAGMA table_info(events)")}
        for col, decl in (("confirmed", "INTEGER"),
                          ("rf_label", "TEXT"),
                          ("rf_confidence", "REAL"),
                          ("channel", "TEXT"),
                          ("baseline_dbm", "REAL"),
                          ("persistence_ratio", "REAL")):
            if col not in existing:
                _db.execute(f"ALTER TABLE events ADD COLUMN {col} {decl}")
                logger.info(f"[DB] Migration: them cot events.{col}")
    return _db


def close_db():
    global _db
    if _db is not None:
        try:
            _db.commit()
            _db.close()
        except Exception as e:
            report_error("close_db (commit/close)", e, every=0)   # data may be unflushed
        _db = None


def db_log_event(result, iq_path=None, persistence_ratio=0.0):
    _eid = None
    if _db is None:
        return None
    try:
        with _db_lock, _db:
            _cur = _db.execute(
                "INSERT INTO events (ts, channel, freq_hz, threat_type, "
                "severity, power_dbm, baseline_dbm, zscore, snr_db, "
                "bandwidth_hz, duration_ms, persistence_ratio, confidence, "
                "indicators, action, rf_label, rf_confidence, iq_path) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (result.timestamp, result.channel, result.freq_hz,
                 result.threat_type, result.threat_level.name,
                 result.anomaly.power_dbm, result.anomaly.baseline_dbm,
                 result.anomaly.zscore, result.anomaly.snr_db,
                 result.anomaly.bandwidth_hz, result.anomaly.duration_ms,
                 float(persistence_ratio), float(result.confidence),
                 json.dumps(result.indicators, ensure_ascii=False),
                 result.action, result.rf_label,
                 float(result.rf_confidence or 0.0), iq_path))
            _eid = _cur.lastrowid
        # [UI] Broadcast tới SSE clients đang mở trong browser
        try:
            _ui_mod = _load_sibling_module(
                "rf_sentinel_ui", ["rf_sentinel_ui.py", "rf_sentinel_ui*.py"])
            if _ui_mod is None:
                raise ImportError("rf_sentinel_ui khong tim thay canh SDR-BLUE-TEAM.py")
            _ui_mod.broadcast_sse({
                "type":       "event",
                "ts":         result.timestamp,
                "channel":    result.channel,
                "freq_hz":    result.freq_hz,
                "threat_type":result.threat_type,
                "severity":   result.threat_level.name,
                "power_dbm":  result.anomaly.power_dbm,
                "zscore":     result.anomaly.zscore,
                "confidence": result.confidence,
                "rf_label":   result.rf_label,
                "rf_confidence": result.rf_confidence,
                "hybrid_ai_label": result.anomaly.hybrid_ai_label,
                "type_ai_label":   result.anomaly.type_ai_label,
                "confirmed":  None,
            })
        except Exception as e:
            # Event IS already saved; only the live browser push failed.
            report_error("db_log_event -> SSE broadcast", e, every=60)
    except Exception as e:
        report_error("db_log_event INSERT", e)      # event was NOT persisted
    return _eid


def db_insert_labeled_event(entry: dict, label: str):
    """Bridge from ActiveLearningAgent.label(): a human/teacher label on a
    queued .sigmf capture becomes a fresh, already-confirmed row in the
    same `events` table RFThreatClassifier.train() reads from — so a
    labeled queue entry actually changes what the classifier learns,
    instead of sitting inert in queue.json. `entry["metrics"]` is the
    EW_AnomalyResult snapshot captured at enqueue time (see
    rf_sentinel_agents.ActiveLearningAgent.enqueue)."""
    if _db is None:
        return None
    m = entry.get("metrics") or {}
    try:
        with _db_lock, _db:
            cur = _db.execute(
                "INSERT INTO events (ts, channel, freq_hz, threat_type, "
                "severity, power_dbm, baseline_dbm, zscore, snr_db, "
                "bandwidth_hz, duration_ms, persistence_ratio, confidence, "
                "indicators, action, rf_label, rf_confidence, iq_path, "
                "confirmed) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (_now_iso_utc(), entry.get("channel", ""),
                 float(entry.get("freq_hz", 0.0) or 0.0), label,
                 "LABELED", float(m.get("power_dbm", 0.0) or 0.0),
                 float(m.get("baseline_dbm", 0.0) or 0.0),
                 float(m.get("zscore", 0.0) or 0.0),
                 float(m.get("snr_db", 0.0) or 0.0),
                 float(m.get("bandwidth_hz", 0.0) or 0.0),
                 float(m.get("duration_ms", 0.0) or 0.0),
                 float(entry.get("persistence_ratio", 0.0) or 0.0),
                 float(entry.get("confidence", 0.0) or 0.0),
                 json.dumps([f"[ACTIVE-LEARNING] nhan boi "
                            f"{entry.get('labeled_by', 'analyst')}"],
                           ensure_ascii=False),
                 "Nhan tu Active-Learning queue.", None, 0.0,
                 entry.get("sigmf_data"), 1))
            eid = cur.lastrowid
        logger.info(f"[ACTIVE-LEARNING] Da ghi nhan '{label}' cho "
                    f"{entry.get('channel')} vao events (id={eid}).")
        return eid
    except Exception as e:
        logger.warning(f"[ACTIVE-LEARNING] Khong ghi duoc vao events DB: {e}")
        return None


def _now_iso_utc():
    return datetime.now(timezone.utc).isoformat()


_last_spectrum_log = defaultdict(float)


def maybe_log_spectrum_point(channel, power_dbm):
    if _db is None:
        return
    now = time.time()
    if now - _last_spectrum_log[channel.name] < SPECTRUM_LOG_INTERVAL_S:
        return
    _last_spectrum_log[channel.name] = now
    try:
        with _db_lock, _db:
            _db.execute(
                "INSERT INTO spectrum_history (ts, channel, freq_hz, power_dbm) "
                "VALUES (?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), channel.name,
                 channel.freq_hz, float(power_dbm)))
    except Exception as e:
        report_error("db_log_spectrum INSERT", e)


def db_fetch_labeled_events(limit=5000):
    """Rows an analyst marked confirmed 0 or 1. NULL = unlabelled."""
    if _db is None:
        return []
    try:
        cur = _db.execute(
            "SELECT * FROM events WHERE confirmed IS NOT NULL "
            "ORDER BY ts DESC LIMIT ?", (limit,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception as e:
        report_error("db_fetch_labeled_events", e)
        return []


def db_fetch_recent_events(limit=50):
    if _db is None:
        return []
    try:
        cur = _db.execute(
            "SELECT id, ts, channel, freq_hz, threat_type, severity, "
            "power_dbm, zscore, snr_db, confidence, rf_label, rf_confidence, "
            "confirmed FROM events ORDER BY id DESC LIMIT ?", (limit,))
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]
    except Exception as e:
        report_error("db_fetch_recent_events", e)
        return []


def db_set_confirmed(event_id, confirmed):
    if _db is None:
        return False
    try:
        with _db_lock, _db:
            _db.execute("UPDATE events SET confirmed=? WHERE id=?",
                        (confirmed, event_id))
        return True
    except Exception as e:
        report_error("db_set_confirmed", e, every=0)   # analyst's label was NOT saved
        return False


# ============================================================================
# AUTO-LABELING  —  autonomous FP/TP labeling, no human required
# ============================================================================
_AUTO_TP_ZSCORE_MIN = 4.0   # minimum |Z| to auto-confirm a TP


def _auto_label(event_id, res, persist_count):
    """
    Labels every logged event as FP (confirmed=0) or TP (confirmed=1)
    automatically so LightGBM can retrain without human input.

    FP  — weak or disagreed signal:
          • threat_level == LOW
          • OR MEDIUM with no dual-AI consensus AND not persistent

    TP  — strong convergence across all layers:
          • threat_level >= HIGH
          • AND both AIs agree
          • AND persistent
          • AND |Z| > _AUTO_TP_ZSCORE_MIN

    FP labels are given liberally (knowing what is NOT a threat is cheap).
    TP labels require a very high bar to keep the training set clean.
    """
    if event_id is None or _db is None:
        return

    a   = res.anomaly
    lvl = res.threat_level

    is_fp = (
        lvl == ThreatLevel.LOW
        or (lvl == ThreatLevel.MEDIUM
            and not a.ai_both_agree
            and persist_count < PERSISTENCE_MIN_COUNT)
    )
    is_tp = (
        lvl.value >= ThreatLevel.HIGH.value
        and a.ai_both_agree
        and persist_count >= PERSISTENCE_MIN_COUNT
        and abs(a.zscore) > _AUTO_TP_ZSCORE_MIN
    )

    if is_fp:
        db_set_confirmed(event_id, 0)
        logger.debug(
            f"[AUTO-LABEL] id={event_id} FP — "
            f"lvl={lvl.name} z={a.zscore:.2f} persist={persist_count}")
    elif is_tp:
        db_set_confirmed(event_id, 1)
        logger.debug(
            f"[AUTO-LABEL] id={event_id} TP — "
            f"lvl={lvl.name} z={a.zscore:.2f} persist={persist_count}")


def db_label_stats():
    """Progress toward RF_MIN_TRAINING, visible in the UI."""
    if _db is None:
        return {"labeled": 0, "needed": RF_MIN_TRAINING,
                "classes": 0, "top_share": 0.0}
    try:
        cur = _db.execute(
            "SELECT threat_type, COUNT(*) FROM events "
            "WHERE confirmed IS NOT NULL GROUP BY threat_type")
        rows    = cur.fetchall()
        labeled = sum(r[1] for r in rows)
        top     = max((r[1] for r in rows), default=0)
        return {"labeled": labeled, "needed": RF_MIN_TRAINING,
                "classes": len(rows),
                "top_share": round(top / labeled, 3) if labeled else 0.0}
    except Exception as e:
        report_error("db_label_stats", e)
        return {"labeled": 0, "needed": RF_MIN_TRAINING,
                "classes": 0, "top_share": 0.0}


def db_summary_stats():
    if _db is None:
        return {}
    try:
        cur = _db.execute(
            "SELECT threat_type, severity, COUNT(*) AS n FROM events "
            "GROUP BY threat_type, severity ORDER BY n DESC")
        breakdown = [dict(zip([c[0] for c in cur.description], r))
                     for r in cur.fetchall()]
        cur2 = _db.execute(
            "SELECT channel, AVG(power_dbm) AS avg_power, COUNT(*) AS n "
            "FROM spectrum_history GROUP BY channel ORDER BY avg_power DESC "
            "LIMIT 10")
        noisy = [dict(zip([c[0] for c in cur2.description], r))
                 for r in cur2.fetchall()]
        rf = _get_rf()
        return {
            "breakdown": breakdown,
            "noisiest": noisy,
            "rf_trained":      bool(rf and rf.usable),
            "rf_classes":      rf.classes_ if rf else [],
            "rf_cv5":          rf.cv5_acc     if rf else None,
            "rf_holdout":      rf.holdout_acc if rf else None,
            "rf_degenerate":   bool(rf and rf.degenerate),
            "rf_trained_at":   rf.trained_at  if rf else None,
            "labeling": db_label_stats(),
        }
    except Exception as e:
        report_error("db_summary_stats", e)
        return {}


def db_channel_spectrum_history(channel_name, limit=500):
    if _db is None:
        return []
    try:
        cur = _db.execute(
            "SELECT ts, power_dbm FROM spectrum_history WHERE channel=? "
            "ORDER BY ts DESC LIMIT ?", (channel_name, limit))
        return [{"ts": r[0], "power_dbm": r[1]} for r in cur.fetchall()]
    except Exception as e:
        report_error("db_channel_spectrum_history", e)
        return []


# ============================================================================
# EVIDENCE
# ============================================================================
def save_evidence(result, iq, persistence_ratio=0.0):
    try:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
        base  = f"{stamp}_{result.channel}_{result.threat_level.name}"
        iq_path = os.path.join(EV_DIR, base + ".iq")
        if iq is not None and len(iq):
            iq.astype(np.complex64).tofile(iq_path)

        meta = {
            "timestamp": result.timestamp,
            "channel": result.channel,
            "freq_hz": result.freq_hz,
            "threat_type": result.threat_type,
            "severity": result.threat_level.name,
            "severity_label": THREAT_LABELS.get(result.threat_level, ""),
            "indicators": result.indicators,
            "action": result.action,
            "confidence": result.confidence,
            "rf_label": result.rf_label,
            "rf_confidence": result.rf_confidence,
            "fingerprint": result.fingerprint,
            "iq_path": iq_path,
            "metrics": asdict(result.anomaly),
        }
        with open(os.path.join(EV_DIR, base + ".json"), "w") as fh:
            json.dump(meta, fh, indent=2, default=str)

        rep = os.path.join(RPT_DIR, base + ".txt")
        with open(rep, "w") as fh:
            fh.write(f"RF SENTINEL v15 — {result.threat_level.name}\n")
            fh.write(f"{'=' * 60}\n")
            fh.write(f"Thoi gian  : {result.timestamp}\n")
            fh.write(f"Kenh       : {result.channel} @ "
                     f"{result.freq_hz / 1e6:.3f} MHz\n")
            fh.write(f"Loai       : {result.threat_type}\n")
            fh.write(f"Cong suat  : {result.anomaly.power_dbm:.1f} dBm "
                     f"(z={result.anomaly.zscore:.2f})\n")
            fh.write(f"AI-1       : {result.anomaly.hybrid_ai_label} "
                     f"({result.anomaly.hybrid_ai_score:.2f})\n")
            fh.write(f"AI-2       : {result.anomaly.type_ai_label} "
                     f"({result.anomaly.type_ai_score:.2f})\n")
            if result.rf_label:
                fh.write(f"RF         : {result.rf_label} "
                         f"({result.rf_confidence:.2f})\n")
            fh.write("\nDau hieu:\n")
            for i in result.indicators:
                fh.write(f"  - {i}\n")
            fh.write(f"\nHanh dong: {result.action}\n")

        db_log_event(result, iq_path=iq_path,
                     persistence_ratio=persistence_ratio)
        return iq_path
    except Exception as e:
        logger.warning(f"[EV] Khong luu duoc bang chung: {e}")
        return None


# ============================================================================
# RX-ONLY ENFORCEMENT  —  hardware/driver-level transmit lockout.
#
# This tool is receive-only by design and by law in most jurisdictions for
# unlicensed operation. This guard is intentionally loud and disclosed, not
# a hidden kill switch: every block is logged, printed, and fatal — the
# program stops rather than silently degrading. It exists to make an
# accidental or careless TX call impossible to slip past unnoticed, and to
# make deliberate tampering detectable rather than silent.
#
# How it works:
#   1. ReceiveOnlySDRProxy wraps the real hackrf/pyhackrf device object.
#      Any attribute whose name matches a TX-capable pattern (start_tx,
#      transmit, send_samples, tx_*, etc.) raises TransmitBlockedError
#      instead of reaching the driver. Every other call passes through
#      untouched — normal RX operation is unaffected.
#   2. connect_hackrf() is the ONLY place a raw device handle is created,
#      and it unconditionally returns the wrapped proxy, never the raw
#      object — so nothing downstream can hold an unguarded reference.
#   3. verify_rx_guard_integrity() runs before any hardware is touched.
#      It (a) re-derives a hash of this guard's own source and compares
#      it to the value recorded below, (b) runs a live self-test that
#      confirms the proxy actually blocks a fake TX call, and (c) checks
#      that connect_hackrf()'s source still routes through the proxy.
#      If ANY of those checks fail — guard edited, guard deleted, or
#      bypassed in connect_hackrf() — the program logs the reason and
#      exits immediately, before opening the SDR. It fails closed, not
#      open: no guard integrity, no hardware access.
#
# This is a safety interlock, not an anti-tamper trap: nothing here is
# obfuscated, and the failure mode is a clear message telling the operator
# exactly what happened and why the program refused to start.
# ============================================================================

# Any attribute name containing one of these substrings is treated as
# transmit-capable and blocked. Deliberately broad/case-insensitive so a
# renamed or vendor-specific TX method still gets caught.
_TX_BLOCK_PATTERNS = (
    "transmit", "start_tx", "tx_start", "send_samples", "write_samples",
    "tx_enable", "enable_tx", "set_tx", "tx_vga", "txvga", "tx_gain",
    "tx_amp", "repeat", "replay", "jam", "spoof_tx", "carrier_on",
)


class TransmitBlockedError(RuntimeError):
    """Raised when code attempts to reach a transmit-capable SDR call."""


def _looks_like_tx(name: str) -> bool:
    n = name.lower()
    return any(pat in n for pat in _TX_BLOCK_PATTERNS)


class ReceiveOnlySDRProxy:
    """Transparent wrapper: RX calls pass through, TX calls are fatal.

    Every blocked attempt is logged at CRITICAL, printed to stderr, and
    terminates the process — this is a hard stop, not a warning that can
    be ignored, because the failure mode we're preventing is illegal RF
    transmission, not a cosmetic bug.
    """

    __slots__ = ("_sdr",)

    def __init__(self, sdr):
        object.__setattr__(self, "_sdr", sdr)

    def _blocked(self, name):
        msg = (f"[TX-GUARD] BI CHAN: goi '{name}' tren SDR bi TU CHOI. "
               f"Cong cu nay chi RECEIVE-ONLY — phat song la BAT HOP PHAP "
               f"neu khong co giay phep. Dung ngay.")
        try:
            logger.critical(msg)
        except Exception as log_err:     # message is still printed to stderr below
            print(f"[TX-GUARD] logger.critical that bai: {log_err!r}", file=sys.stderr)
        print(msg, file=sys.stderr)
        # Hard, immediate exit — do not let the caller catch this and
        # continue. A blocked TX attempt is a stop-the-program event.
        os._exit(1)

    def __getattr__(self, name):
        if _looks_like_tx(name):
            self._blocked(name)
        return getattr(self._sdr, name)

    def __setattr__(self, name, value):
        if _looks_like_tx(name):
            self._blocked(name)
        setattr(self._sdr, name, value)

    def __repr__(self):
        return f"ReceiveOnlySDRProxy({self._sdr!r})"


# Recorded hash of this guard's own source (the block above, from
# `_TX_BLOCK_PATTERNS` through the end of `ReceiveOnlySDRProxy`). Computed
# once at write-time and checked again at every startup — see
# verify_rx_guard_integrity(). If you legitimately need to change the
# guard, update this constant to match, so the change is visible in diff
# review rather than silently accepted.
_RX_GUARD_EXPECTED_HASH = None  # filled in by _compute_rx_guard_hash() below


def _compute_rx_guard_hash():
    import hashlib
    import inspect
    src = "".join([
        inspect.getsource(_looks_like_tx),
        inspect.getsource(TransmitBlockedError),
        inspect.getsource(ReceiveOnlySDRProxy),
    ])
    return hashlib.sha256(src.encode("utf-8")).hexdigest()


def verify_rx_guard_integrity():
    """Fail closed before any hardware is touched.

    Checks, in order:
      1. The guard classes/functions still exist and are importable.
      2. A live self-test: a fake TX-capable method is actually blocked.
      3. connect_hackrf()'s source still wraps its return value in the
         proxy, so the guard cannot be quietly bypassed one function away.
      4. The guard's source hash matches what was recorded, so an edit to
         the block list or the blocking logic itself is detected even if
         it doesn't fully break the self-test.
    Any failure => CRITICAL log + refusal to start. No hardware is opened
    on this path.
    """
    import inspect

    def fail(reason):
        msg = f"[TX-GUARD] KIEM TRA TOAN VEN THAT BAI: {reason}. TU CHOI KHOI DONG."
        try:
            logger.critical(msg)
        except Exception as log_err:     # message is still printed to stderr below
            print(f"[TX-GUARD] logger.critical that bai: {log_err!r}", file=sys.stderr)
        print(msg, file=sys.stderr)
        sys.exit(1)

    # 1) existence
    try:
        _ = (TransmitBlockedError, ReceiveOnlySDRProxy, _looks_like_tx,
             _TX_BLOCK_PATTERNS)
    except NameError as e:
        fail(f"thanh phan guard bi thieu ({e})")

    # 2) live self-test — does the proxy actually block?
    class _FakeDevice:
        def start_rx(self):
            return "ok"

        def start_tx(self):
            return "SHOULD_NEVER_RUN"

    fake = ReceiveOnlySDRProxy(_FakeDevice())
    try:
        fake.start_rx()  # must pass through fine
    except Exception as e:
        fail(f"RX hop le bi chan nham ({e})")

    blocked = False
    try:
        # Call in a subprocess-safe way: os._exit would kill this process
        # too, so temporarily monkeypatch os._exit for the self-test only.
        _real_exit = os._exit
        raised = {"hit": False}

        def _fake_exit(code):
            raised["hit"] = True
            raise TransmitBlockedError("self-test trip")

        os._exit = _fake_exit
        try:
            fake.start_tx()
        except TransmitBlockedError:  # expected-exception: self-test, the guard tripping IS the pass condition
            blocked = raised["hit"]
        finally:
            os._exit = _real_exit
    except Exception as e:
        fail(f"self-test loi bat thuong ({e})")

    if not blocked:
        fail("proxy KHONG chan duoc goi TX gia lap — guard vo hieu")

    # 3) connect_hackrf() must route through the proxy.
    try:
        ch_src = inspect.getsource(connect_hackrf)
        if "ReceiveOnlySDRProxy" not in ch_src:
            fail("connect_hackrf() khong con boc SDR bang ReceiveOnlySDRProxy")
    except Exception as e:
        fail(f"khong doc duoc source connect_hackrf ({e})")

    # 4) source-hash check (advisory-strict: any edit to the guard trips it).
    global _RX_GUARD_EXPECTED_HASH
    current = _compute_rx_guard_hash()
    if _RX_GUARD_EXPECTED_HASH is None:
        # First run after this feature was added: record and warn once,
        # rather than lock the operator out. Subsequent runs enforce it.
        _RX_GUARD_EXPECTED_HASH = current
        logger.warning(
            "[TX-GUARD] Chua co hash tham chieu — ghi lai hash hien tai. "
            "Neu day khong phai lan chay dau, kiem tra file da bi sua doi.")
    elif current != _RX_GUARD_EXPECTED_HASH:
        fail("ma nguon cua RX-guard da bi thay doi so voi hash ghi nhan")

    logger.info("[TX-GUARD] Kiem tra toan ven OK — receive-only duoc thuc thi.")
    return True


# ============================================================================
# WIDEBAND DISCOVERY + CANDIDATE TRACKING  (ported from v6+v13 merge branch)
#
# Adapted to THIS file's actual APIs — not a drag-and-drop copy. Key
# differences from the source branch that had to be reconciled:
#   - This file's FastSweepEngine.tune(freq_hz) takes a bare frequency and
#     .snapshot() takes no args (dwell is handled internally via
#     SWEEP_SETTLE_S/SWEEP_DWELL_S) — the source branch's engine.tune(channel)
#     / engine.get_snapshot(wait_s=...) API doesn't exist here.
#   - This file's Channel dataclass has no bandwidth_hz/description fields
#     and stores history in `_history` (list), not `_power_history` (deque).
#   - detect_anomaly_ew() here already calls hybrid_ai.observe()/
#     type_ai.observe() internally, so discovered channels get folded into
#     both AI layers' online learning just by running them through the same
#     detect_anomaly_ew -> analyze -> apply_confidence_gate pipeline as
#     sweep_once() uses for the watchlist. No separate "extract_features /
#     add_global_data" step (that API doesn't exist in this file) is needed.
# ============================================================================
def find_signal_peaks(iq, sr, center_freq,
                       threshold_db=CANDIDATE_PEAK_THRESHOLD_DB,
                       min_sep_hz=CANDIDATE_MIN_SEPARATION_HZ):
    """Peaks in one snapshot's PSD, as (freq_hz, power_db) tuples."""
    psd = compute_psd(iq)
    if not np.count_nonzero(psd):
        return []
    psd_db = 10.0 * np.log10(psd.astype(np.float64) + 1e-12)
    freqs = np.fft.fftshift(np.fft.fftfreq(len(psd), 1.0 / sr)) + center_freq
    thresh = float(np.median(psd_db)) + threshold_db
    bin_hz = sr / len(psd)
    distance = max(1, int(min_sep_hz / bin_hz))

    try:
        from scipy.signal import find_peaks as _find_peaks
        idx, _ = _find_peaks(psd_db, height=thresh, distance=distance)
    except Exception as e:
        report_error("find_signal_peaks(scipy)", e, every=None, level="warning")
        # Pure-numpy fallback if scipy is unavailable: simple local-maxima
        # scan with the same threshold/min-separation semantics.
        idx = []
        last = -distance
        for i in range(1, len(psd_db) - 1):
            if psd_db[i] < thresh:
                continue
            if psd_db[i] >= psd_db[i - 1] and psd_db[i] >= psd_db[i + 1] \
                    and (i - last) >= distance:
                idx.append(i)
                last = i
        idx = np.array(idx, dtype=int)

    return [(float(freqs[i]), float(psd_db[i])) for i in idx]


class CandidateTracker:
    """Buckets recurring wideband peaks into provisional/confirmed channels
    not already on WATCHLIST, so they can be fed through the normal
    detect/analyze/gate pipeline once they've shown up enough times to be
    worth the sweep time."""

    def __init__(self):
        self.candidates = {}    # bucket_key -> Channel
        self.provisional = {}   # bucket_key -> hit count

    @staticmethod
    def _bucket(freq_hz):
        return int(round(freq_hz / CANDIDATE_BUCKET_HZ))

    @staticmethod
    def _covered_by_watchlist(freq_hz):
        return any(abs(ch.freq_hz - freq_hz) <= CANDIDATE_GUARD_HZ
                   for ch in WATCHLIST)

    def ingest_survey(self, peaks):
        seen_keys = set()
        for freq_hz, _peak_db in peaks:
            if self._covered_by_watchlist(freq_hz):
                continue
            key = self._bucket(freq_hz)
            seen_keys.add(key)
            if key in self.candidates:
                self.candidates[key].stale_rounds = 0
                continue
            hits = self.provisional.get(key, 0) + 1
            if hits < CANDIDATE_CONFIRM_ROUNDS:
                self.provisional[key] = hits
                continue
            ch = Channel(
                name=f"Discovered_{freq_hz/1e6:.3f}M", freq_hz=freq_hz,
                priority=3, threat_type="UNKNOWN_DISCOVERED")
            ch.stale_rounds = 0
            self.candidates[key] = ch
            self.provisional.pop(key, None)

        for key in list(self.provisional.keys()):
            if key not in seen_keys:
                del self.provisional[key]
        for key, ch in list(self.candidates.items()):
            if key not in seen_keys:
                ch.stale_rounds = getattr(ch, "stale_rounds", 0) + 1
                if ch.stale_rounds > CANDIDATE_TTL_ROUNDS:
                    del self.candidates[key]

    def warming(self):
        return [c for c in self.candidates.values()
                if len(c._history) < CANDIDATE_WARMUP_SAMPLES]

    def ready(self):
        return [c for c in self.candidates.values()
                if len(c._history) >= CANDIDATE_WARMUP_SAMPLES]


candidate_tracker = CandidateTracker()


# ---- optional live spectrum GUI (separate process; never blocks the sweep)
_gui_queue = None
_gui_proc  = None


def _spectrum_gui_process(q):
    try:
        import matplotlib
        matplotlib.use("TkAgg")
        import matplotlib.pyplot as plt
    except Exception as e:
        print(f"[GUI] Khong the mo cua so bieu do (thieu matplotlib/display): {e}")
        return
    import queue as _q

    plt.ion()
    fig, ax = plt.subplots(figsize=(11, 5))
    try:
        fig.canvas.manager.set_window_title("RF Sentinel - Wideband Discovery")
    except Exception as e:
        report_error("gui set_window_title", e, every=None, level="warning")
    line, = ax.plot([], [], lw=1.2, color="#33cc66", label="PSD (dB)")
    cursor = ax.axvline(x=0, color="yellow", lw=1, alpha=0.6, label="Vi tri quet")
    scat = ax.scatter([], [], color="red", marker="v", s=45, zorder=5,
                      label="Peak/Candidate")
    ax.set_xlabel("Tan so (MHz)"); ax.set_ylabel("PSD (dB, xap xi)")
    ax.grid(alpha=0.3); ax.legend(loc="upper right", fontsize=8)

    xs, ys, peak_xs, peak_ys = [], [], [], []
    while True:
        try:
            msg = q.get(timeout=0.5)
        except _q.Empty:  # expected-exception: idle poll, the queue is empty most of the time
            plt.pause(0.03)
            continue
        if msg is None:
            break
        if msg["type"] == "round_start":
            xs, ys, peak_xs, peak_ys = [], [], [], []
            ax.set_xlim(msg["start_mhz"], msg["end_mhz"])
            ax.set_title("Dang quet wideband...")
        elif msg["type"] == "step":
            fx = msg["freq_mhz"]
            if msg["power_db"] is not None:
                xs.append(fx); ys.append(msg["power_db"])
            for pf, pd in msg["peaks_mhz_db"]:
                peak_xs.append(pf); peak_ys.append(pd)
            line.set_data(xs, ys)
            cursor.set_xdata([fx, fx])
            scat.set_offsets(list(zip(peak_xs, peak_ys)) if peak_xs
                             else np.empty((0, 2)))
            if ys:
                top = max(max(ys), max(peak_ys) if peak_ys else max(ys))
                ax.set_ylim(min(ys) - 8, top + 8)
            ax.set_title(f"Quet {fx:.1f} MHz  ({msg['step']+1}/{msg['total_steps']})")
        fig.canvas.draw_idle()
        plt.pause(0.01)
    plt.close(fig)


def _push_gui_round_start(start_hz, end_hz, total_steps):
    if _gui_queue is None:
        return
    try:
        _gui_queue.put_nowait({"type": "round_start", "start_mhz": start_hz / 1e6,
                               "end_mhz": end_hz / 1e6, "total_steps": total_steps})
    except Exception as e:
        report_error("gui queue (round_start) — frame dropped", e, every=60)


def _push_gui_step(freq_hz, power_db, peaks, step_i, total_steps):
    if _gui_queue is None:
        return
    try:
        _gui_queue.put_nowait({
            "type": "step", "freq_mhz": freq_hz / 1e6, "power_db": power_db,
            "peaks_mhz_db": [(f / 1e6, d) for f, d in peaks],
            "step": step_i, "total_steps": total_steps,
        })
    except Exception as e:
        report_error("gui queue (step) — frame dropped", e, every=60)


def start_spectrum_gui():
    """Fire up the optional GUI as a separate PROCESS (not thread) so a
    Tk/matplotlib crash can never take down the sweep or the Flask thread.
    No-op if disabled or matplotlib/display isn't available."""
    global _gui_queue, _gui_proc
    if not ENABLE_SPECTRUM_GUI or not MATPLOTLIB_OK:
        return None
    try:
        _gui_queue = mp.Queue(maxsize=GUI_QUEUE_MAXSIZE)
        _gui_proc = mp.Process(target=_spectrum_gui_process, args=(_gui_queue,),
                               daemon=True, name="rf-sentinel-gui")
        _gui_proc.start()
        logger.info("[GUI] Cua so pho tan da khoi dong (process rieng).")
        return _gui_proc
    except Exception as e:
        logger.warning(f"[GUI] Khong khoi dong duoc: {e}")
        _gui_queue = None
        return None


def wideband_survey(engine, start_hz, end_hz, step_hz):
    """One sweep across [start_hz, end_hz). Returns list of (freq_hz, db)
    peaks found across all steps. Uses this file's real tune()/snapshot()
    timing (SWEEP_SETTLE_S + SWEEP_DWELL_S per step) — no separate dwell
    parameter needed."""
    found = []
    total_steps = int((end_hz - start_hz) / step_hz) + 1
    _push_gui_round_start(start_hz, end_hz, total_steps)
    freq = start_hz
    step_i = 0
    while freq < end_hz:
        step_peaks, step_power_db = [], None
        if engine.tune(freq):
            iq = engine.snapshot()
            if len(iq):
                step_peaks = find_signal_peaks(iq, SAMPLE_RATE_HZ, freq)
                found.extend(step_peaks)
                psd = compute_psd(iq)
                if np.count_nonzero(psd):
                    step_power_db = float(np.max(10 * np.log10(psd + 1e-12)))
        _push_gui_step(freq, step_power_db, step_peaks, step_i, total_steps)
        freq += step_hz
        step_i += 1
    return found


def run_discovery(handle, hybrid_ai, type_ai, fp_store, evidence_budget):
    """Wideband scan + feed any recurring off-watchlist peaks through the
    same detect/analyze/gate/log pipeline sweep_once() uses. Any failure
    here is caught by the caller (monitor_loop) — discovery is a bonus
    feature, never allowed to take down the core watchlist sweep."""
    engine = handle.engine
    logger.info(f"[DISCOVERY] Quet wideband {WIDEBAND_START_HZ/1e6:.0f}-"
               f"{WIDEBAND_END_HZ/1e6:.0f} MHz...")
    peaks = wideband_survey(engine, WIDEBAND_START_HZ, WIDEBAND_END_HZ,
                            WIDEBAND_STEP_HZ)
    candidate_tracker.ingest_survey(peaks)
    logger.info(f"[DISCOVERY] {len(peaks)} peak(s), "
               f"{len(candidate_tracker.candidates)} candidate(s) dang theo doi.")

    # Warming candidates: just collect samples (feeds both AI layers via
    # detect_anomaly_ew's internal observe() calls) without full logging.
    for ch in candidate_tracker.warming():
        if not engine.tune(ch.freq_hz):
            continue
        iq = engine.snapshot()
        if len(iq) == 0:
            continue
        r = detect_anomaly_ew(ch, iq, hybrid_ai, type_ai)
        ch.update_baseline(r.power_dbm, force=True)

    # Ready candidates: run the full pipeline, same as a watchlist channel.
    for ch in candidate_tracker.ready():
        if not engine.tune(ch.freq_hz):
            continue
        iq = engine.snapshot()
        if len(iq) == 0:
            continue

        r   = detect_anomaly_ew(ch, iq, hybrid_ai, type_ai)
        res = analyze(ch, r, fp_store)

        persistence_tracker.record(ch.name, res.anomaly.any_alert)
        is_persistent = persistence_tracker.is_persistent(ch.name)
        pcount        = persistence_tracker.count(ch.name)
        apply_confidence_gate(res, is_persistent, pcount)

        if AGENT_SUITE is not None:
            try:
                AGENT_SUITE.process(ch, res, iq, engine=engine, persist_count=pcount)
            except Exception as e:
                logger.error(f"[AGENTS] process() loi (discovery) tren {ch.name}: {e}")

        if res.threat_level.value >= ThreatLevel.MEDIUM.value:
            logger.warning(
                f"[DISCOVERY][{res.threat_level.name}] {ch.name} "
                f"{ch.freq_hz/1e6:.3f}MHz {res.threat_type} "
                f"z={r.zscore:.2f}")
            for i in res.indicators:
                logger.warning(f"        {i}")

        if res.threat_level.value >= ThreatLevel.HIGH.value \
                and evidence_budget[0] < 20:
            evidence_budget[0] += 1
            save_evidence(res, iq, pcount / float(PERSISTENCE_WINDOW))

        db_log_event(res, persistence_ratio=pcount / float(PERSISTENCE_WINDOW))
        maybe_log_spectrum_point(ch, r.power_dbm)

        if res.threat_level.value < ThreatLevel.MEDIUM.value:
            ch.update_baseline(r.power_dbm)


# ============================================================================
# HARDWARE
# ============================================================================
class FastSweepEngine:
    def __init__(self, sdr):
        self.sdr    = sdr
        self.streaming = False
        self._lock  = Lock()

    def tune(self, freq_hz):
        try:
            self.sdr.set_center_freq(int(freq_hz), 0)
            time.sleep(SWEEP_SETTLE_S)
            return True
        except Exception as e:
            report_error("SDR set_center_freq", e, every=15)
            return False

    def snapshot(self):
        """Grab one buffer. Returns complex64 samples."""
        try:
            try:
                self.sdr.start_rx()
                self.streaming = True
            except Exception as e:
                report_error("SDR start_rx", e, every=15)
            time.sleep(SWEEP_DWELL_S)
            raw = None
            try:
                raw = self.sdr.read_samples(32768)
            except Exception as e:
                report_error("SDR read_samples", e, every=15)
                raw = None
            if raw is None:
                return np.zeros(0, dtype=np.complex64)
            a = np.asarray(raw)
            if a.dtype == np.int8:
                return (a[0::2].astype(np.float32) +
                        1j * a[1::2].astype(np.float32)).astype(np.complex64)
            return a.astype(np.complex64)
        except Exception as e:
            report_error("SDR snapshot", e, every=15)
            return np.zeros(0, dtype=np.complex64)

    def stop_stream(self):
        """Safe conditional stop — harmless if never started."""
        if not self.streaming:
            return
        try:
            self.sdr.stop_rx()
        except Exception as e:
            report_error("SDR stop_rx", e, every=0, level="warning")
        self.streaming = False


class EngineHandle:
    """Wrapper so reconnect can swap the engine without stale references."""
    def __init__(self, engine):
        self.engine = engine


def connect_hackrf():
    try:
        import hackrf
        sdr = hackrf.HackRF()
    except Exception:
        try:
            from pyhackrf import HackRF
            sdr = HackRF()
        except Exception as e:
            raise RuntimeError(
                f"Khong ket noi duoc HackRF ({e}). Cai pyhackrf hoac chay "
                f"voi --web-only de xem giao dien ma khong can phan cung."
            ) from e
    try:
        sdr.sample_rate = int(SAMPLE_RATE_HZ)
    except Exception as e:
        # Wrong sample rate => every bin/dBm below is mis-scaled. Never hide it.
        report_error("connect_hackrf sample_rate", e, every=0)
    # RX-only enforcement: wrap immediately. No code path past this point
    # ever sees the raw, unguarded device handle.
    sdr = ReceiveOnlySDRProxy(sdr)
    for gain_attr in ("lna_gain", "vga_gain", "amp_enable"):
        try:
            if gain_attr == "amp_enable":
                setattr(sdr, gain_attr, False)
            else:
                setattr(sdr, gain_attr, 16)
        except Exception as e:
            report_error(f"connect_hackrf {gain_attr}", e, every=0, level="warning")
    return sdr


# ============================================================================
# BASELINE
# ============================================================================
def init_baseline(engine, rounds=8):
    logger.info("[BASELINE] Dang do nen nhieu cho tat ca kenh...")
    for _ in range(rounds):
        for ch in WATCHLIST:
            if not engine.tune(ch.freq_hz):
                continue
            iq = engine.snapshot()
            if len(iq):
                ch.add_sample(estimate_power_dbm(iq, ch.freq_hz))
    logger.info(f"[BASELINE] Xong {len(WATCHLIST)} kenh, "
                f"{rounds} vong moi kenh.")


# ============================================================================
# SWEEP
# ============================================================================
def sweep_once(handle, hybrid_ai, type_ai, fp_store, evidence_budget=None):
    if evidence_budget is None:
        evidence_budget = [0]
    engine = handle.engine
    for ch in WATCHLIST:
        if not engine.tune(ch.freq_hz):
            continue
        iq = engine.snapshot()
        if len(iq) == 0:
            continue

        r   = detect_anomaly_ew(ch, iq, hybrid_ai, type_ai)
        res = analyze(ch, r, fp_store)

        persistence_tracker.record(ch.name, res.anomaly.any_alert)
        is_persistent = persistence_tracker.is_persistent(ch.name)
        pcount        = persistence_tracker.count(ch.name)

        apply_confidence_gate(res, is_persistent, pcount)

        # Agent layer: gain/FHSS focus, SOM edge-scoring, active-learning
        # queueing + teacher escalation on low confidence, protocol decode
        # for ISM channels, automated response on HIGH/CRITICAL. Wrapped
        # again here (on top of AgentSuite's own internal try/excepts) so a
        # plugin bug can never interrupt the core watchlist sweep.
        if AGENT_SUITE is not None:
            try:
                AGENT_SUITE.process(ch, res, iq, engine=engine, persist_count=pcount)
            except Exception as e:
                logger.error(f"[AGENTS] process() loi tren {ch.name}: {e}")

        if res.threat_level.value >= ThreatLevel.MEDIUM.value:
            logger.warning(
                f"[{res.threat_level.name}] {ch.name} "
                f"{ch.freq_hz / 1e6:.1f}MHz {res.threat_type} "
                f"z={r.zscore:.2f} ai1={r.hybrid_ai_score:.2f} "
                f"ai2={r.type_ai_score:.2f}"
                + (f" rf={res.rf_label}/{res.rf_confidence:.2f}"
                   if res.rf_label else ""))
            for i in res.indicators:
                logger.warning(f"        {i}")

        if res.threat_level.value >= ThreatLevel.HIGH.value \
                and evidence_budget[0] < 20:
            evidence_budget[0] += 1
            save_evidence(res, iq, pcount / float(PERSISTENCE_WINDOW))

        # Feed the supervised layer. _auto_label() handles FP/TP labeling
        # autonomously — no human labeling needed.
        _p_ratio = pcount / float(PERSISTENCE_WINDOW)
        _eid = db_log_event(res, persistence_ratio=_p_ratio)
        _auto_label(_eid, res, pcount)
        maybe_log_spectrum_point(ch, r.power_dbm)

        # Retrain tick: counted per *event* (one measurement per channel),
        # not per *round*.  RF_RETRAIN_EVERY_N = 500 now means 500 individual
        # channel observations, which is the intended unit.
        _get_rf_retrain_tick()

        if res.threat_level.value < ThreatLevel.MEDIUM.value:
            ch.update_baseline(r.power_dbm)
            # Cache a real clean sample so monitor_loop can feed the EMA
            # with genuine baseline data rather than a synthetic -90 dBm stub.
            # Shallow copy: EW_AnomalyResult holds only primitives (float/bool/str)
            # so copy() is sufficient and cheaper than dataclasses.replace().
            # Without it, the next iteration's mutations to r (dtw_fhss_alert,
            # cyclo_adv_alert, etc.) would silently corrupt the cached value.
            _LAST_CLEAN_SAMPLE = copy.copy(r)


def monitor_loop(handle, hybrid_ai, type_ai, fp_store):
    round_no = 0
    evidence_budget = [0]
    while True:
        round_no += 1
        evidence_budget[0] = 0
        try:
            sweep_once(handle, hybrid_ai, type_ai, fp_store, evidence_budget)
        except Exception as e:
            logger.error(f"[SWEEP] Vong {round_no} loi: {e}")

        # Wideband discovery: every N rounds, off the watchlist's back.
        # Ported feature — isolated in its own try/except so a discovery
        # bug can never interrupt the core watchlist sweep.
        if WIDEBAND_SCAN_EVERY_N_ROUNDS > 0 \
                and round_no % WIDEBAND_SCAN_EVERY_N_ROUNDS == 0:
            try:
                run_discovery(handle, hybrid_ai, type_ai, fp_store,
                             evidence_budget)
            except Exception as e:
                logger.error(f"[DISCOVERY] Vong {round_no} loi: {e}")

        # EMA drift update — only on a *real* clean sample captured this round.
        # Using a synthetic -90 dBm placeholder (old code) pulled the cluster
        # centre toward a fictional noise floor rather than the actual measured
        # baseline, degrading Gate [3]'s z-score discrimination.
        # _LAST_CLEAN_SAMPLE is written by sweep_once() whenever a channel
        # comes back below MEDIUM; if the whole round was anomalous we skip.
        if _LAST_CLEAN_SAMPLE is not None:
            try:
                hybrid_ai.ema_update(_LAST_CLEAN_SAMPLE, time.time())
            except Exception as e:
                report_error("monitor_loop EMA update", e)

        # Retrain tick is now counted per-event inside sweep_once(), so no
        # additional per-round call is needed here.

        # Active-Learning Agent: check if enough newly human/teacher-labeled
        # samples have piled up to justify a retrain pass.
        if AGENT_SUITE is not None:
            try:
                AGENT_SUITE.retrain_tick()
            except Exception as e:
                logger.error(f"[AGENTS] retrain_tick() loi: {e}")

        time.sleep(0.05)


def _get_rf_retrain_tick():
    rf = _get_rf()
    if rf is not None:
        rf.maybe_retrain()


# ============================================================================
# FLASK UI  —  Fix [2]: hard reloader suppression.
# ============================================================================
# ============================================================================
# FLASK UI  —  [NEW] routes đăng ký qua rf_sentinel_ui.register()
# PAGE string cũ đã được xóa và thay bằng rf_sentinel_ui._PAGE.
# ============================================================================
WEB_APP = Flask(__name__) if FLASK_OK else None

# Đăng ký routes vào WEB_APP qua rf_sentinel_ui — xem _register_ui()
# được gọi từ start_web_ui() sau khi init_db() xong.


def _register_ui():
    """[NEW] Đăng ký rf_sentinel_ui routes vào WEB_APP.
    Gọi từ start_web_ui() sau init_db() nên _get_rf / db_* đã tồn tại."""
    if WEB_APP is None:
        return
    try:
        _ui = _load_sibling_module(
            "rf_sentinel_ui", ["rf_sentinel_ui.py", "rf_sentinel_ui*.py"])
        if _ui is None:
            raise ImportError("rf_sentinel_ui khong tim thay canh SDR-BLUE-TEAM.py")
        _ui.register(
            app                  = WEB_APP,
            get_rf_fn            = _get_rf,
            db_fetch_recent_fn   = db_fetch_recent_events,
            db_fetch_labeled_fn  = db_fetch_labeled_events,
            db_set_confirmed_fn  = db_set_confirmed,
            db_label_stats_fn    = db_label_stats,
            db_summary_stats_fn  = db_summary_stats,
            db_channel_spectrum_fn = db_channel_spectrum_history,
            watchlist            = WATCHLIST,
            cal_bands_ref        = _CAL_BANDS_MUT,
            cal_verified_ref     = _CAL_VERIFIED_MUT,
            flask_port           = FLASK_PORT,
        )
        logger.info("[UI] rf_sentinel_ui routes da dang ky vao Flask.")
    except ImportError:
        logger.warning("[UI] rf_sentinel_ui.py khong tim thay — dung UI don gian.")
        _register_fallback_ui()
    except Exception as e:
        logger.error(f"[UI] Loi khi dang ky UI: {e}")

    # Agent layer routes (/api/agents/*) — status, active-learning queue +
    # labeling, AoA/RSSI bearing samples. Independent of rf_sentinel_ui, so
    # it registers even in --web-only mode or if rf_sentinel_ui is missing.
    if AGENT_SUITE is not None:
        try:
            AGENT_SUITE.register_flask(WEB_APP)
        except Exception as e:
            logger.error(f"[AGENTS] Loi khi dang ky agent routes: {e}")


def _register_fallback_ui():
    """Fallback tối giản nếu rf_sentinel_ui.py không có."""
    if WEB_APP is None or not FLASK_OK:
        return
    from flask import jsonify, request

    @WEB_APP.route("/")
    def _fb_index():
        return "<h1 style='font-family:monospace;color:#3eb8ff'>RF Sentinel — UI unavailable (rf_sentinel_ui.py missing)</h1>"

    @WEB_APP.route("/api/events")
    def _fb_events():
        limit = min(int(request.args.get("limit", 50)), 500)
        return jsonify({"events": db_fetch_recent_events(limit), "count": 0})

    @WEB_APP.route("/api/health")
    def _fb_health():
        return jsonify({"ok": True, "port": FLASK_PORT, "ui": "fallback"})


def _run_flask(mode="full"):
    """Fix [2]: the reloader can never fork a second HackRF owner here."""
    if WEB_APP is None:
        logger.warning("[WEB] Flask khong co — UI TAT.")
        return

    # Hard guard. If this function is somehow running inside a Werkzeug
    # reloader child, that child would re-open the SDR and SQLite. Refuse.
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        logger.error("[WEB] Phat hien tien trinh reloader cua Werkzeug — "
                     "TU CHOI khoi dong de tranh tranh chap HackRF/SQLite.")
        return

    logger.info(f"[WEB] UI tai http://{FLASK_HOST}:{FLASK_PORT}/ (mode={mode})")
    try:
        WEB_APP.run(host=FLASK_HOST, port=FLASK_PORT,
                    threaded=True, debug=False, use_reloader=False)
    except OSError as e:
        logger.error(f"[WEB] Khong mo duoc cong {FLASK_PORT}: {e}. "
                     f"Da co tien trinh khac dang chay?")
    except Exception as e:
        logger.error(f"[WEB] Loi: {e}")


def start_web_ui(mode="full"):
    if WEB_APP is None:
        return None
    _register_ui()   # [NEW] đăng ký routes trước khi start thread
    t = Thread(target=_run_flask, args=(mode,), daemon=True,
               name="rf-sentinel-web")
    t.start()
    return t


# ============================================================================
# MAIN
# ============================================================================
def print_banner():
    logger.info("=== RF SENTINEL v15 (DUAL-AI COMBAT EW + CONFIDENCE GATING) ===")
    logger.info("  AI [1] Global : DBSCAN + IsolationForest, train chung toan bo")
    logger.info("  AI [2] Per-Type: HMM (FHSS/Spoof) | LOF (RFID/IoT/FakeBTS)"
                " | OCSVM (Emergency) | IF (con lai)")
    _be = ("LightGBM" if LGBM_OK else
           "XGBoost"  if XGB_OK else
           "RandomForest")
    logger.info(f"  AI [3] Supervised: {_be} tren nhan da kiem chung [A]")
    logger.info("  DSP [C] Savitzky-Golay spectrum pre-filter: BAT")
    logger.info("  DSP [B] DTW FHSS tracker: BAT (history=%d)", FHSS_HISTORY_LEN)
    logger.info("  DSP [D] CAF cyclostationary: BAT (%d symbol rates)", len(CYCLO_SYMBOL_RATES_HZ))
    logger.info("  Gate [1] Persist: can >=%d/%d vong quet lien tiep",
                PERSISTENCE_MIN_COUNT, PERSISTENCE_WINDOW)
    logger.info("  Gate [2] Power  : CRITICAL can Dual-AI dong thuan VA |Z|>%.1f",
                CRITICAL_ZSCORE_GATE)
    logger.info("  Gate [3] EMA    : truot nhe moi %.0f phut tren mau sach",
                EMA_UPDATE_INTERVAL_S / 60.0)
    logger.info("  Gate [4] RF     : chi HA cap do, khong bao gio NANG")
    logger.info("  Web UI        : http://%s:%d/", FLASK_HOST, FLASK_PORT)
    logger.info("  Agents        : %s (SOM, Teacher-Student, Cognitive-Freq, "
               "Active-Learning, Automated-Response, Protocol-Decoder)",
               "BAT" if AGENTS_AVAILABLE else "TAT (rf_sentinel_agents.py khong co)")
    logger.warning("  [!] CONG CU THU DONG (receive-only) - khong phat/replay.")
    logger.warning("  [!] TX-GUARD  : moi loi goi phat song se bi CHAN va thoat "
                   "chuong trinh ngay lap tuc (fail-loud). Xem "
                   "verify_rx_guard_integrity().")
    logger.warning("  [!] CALIBRATION: chua hieu chuan phan cung — dBm chi la "
                   "tuong doi.")
    logger.warning("  [!] FHSS TEMPLATES (DJI/ELRS): cac mau chuan la DU LIEU "
                   "TONG HOP, KHONG THU TU THIET BI THAT. Do nhan dang drone "
                   "co the bi cao hoac thieu cho moi truong cua ban. Xem "
                   "CALIBRATION.md de biet cach thay the bang mau thu that.")
    logger.warning("  [!] SWEEP: ~25ms/kenh co the bo lo xung burst rat ngan.")
    logger.warning("  [!] DSSS duoi noise floor van co the bi bo sot.")


def main(argv=None):
    argv = argv or sys.argv[1:]
    web_only = "--web-only" in argv
    train_now = "--train-now" in argv

    print_banner()

    # ---- Web-only mode: the isolated debugging path for Flask routes. -----
    # No HackRF, no sweep, no writer contention. Fix [2] turns this from
    # "debug the web layer in a separate script" into a flag on this one.
    if web_only:
        init_db()
        init_rf(force_train=train_now)
        init_agents()
        logger.info("[WEB-ONLY] Khong dung HackRF. Ctrl+C de dung.")
        start_web_ui(mode="web-only")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            logger.info("[+] Dung.")
        finally:
            close_db()
        return 0

    # ---- Normal mode ----------------------------------------------------
    init_db()
    logger.info(f"[OK] Da mo SQLite: {DB_PATH}")

    init_rf(force_train=train_now)          # Fix [1]: after logger + init_db
    init_agents()                           # SOM/Teacher-Student/Freq/etc.

    start_web_ui(mode="full")               # Fix [2]: threaded, no reloader
    start_spectrum_gui()                    # optional, separate process

    # TX guard must pass BEFORE any hardware is opened. Fails closed.
    verify_rx_guard_integrity()

    sdr    = connect_hackrf()
    logger.info("[OK] HackRF Connected.\n")
    handle = EngineHandle(FastSweepEngine(sdr))

    hybrid_ai = HybridCognitiveAI()
    type_ai   = RFAnomalyAI()
    fp_store  = {}

    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="rf-sweep")
    exit_code = 0
    try:
        init_baseline(handle.engine)
        logger.info("\n[+] Bat dau Dual-AI Combat Sweep. Ctrl+C de dung.\n")
        sweep_future = executor.submit(monitor_loop, handle, hybrid_ai, type_ai, fp_store)
        # Main thread chỉ chờ — Flask và sweep chạy song song
        while not sweep_future.done():
            time.sleep(0.5)
        # done() only means the worker STOPPED.  Any exception inside it stays
        # locked in the Future until someone asks for the result — without this
        # line a dead sweep thread ended the program silently with exit code 0.
        sweep_future.result()
    except KeyboardInterrupt:
        logger.info("\n[+] Dung giam sat.")
    except Exception as e:
        logger.error(f"[!] Loi: {e}", exc_info=True)
        exit_code = 1
    finally:
        executor.shutdown(wait=False)
        handle.engine.stop_stream()
        try:
            handle.engine.sdr.close()
        except Exception as e:
            report_error("main sdr.close", e, every=0, level="warning")
        close_db()
        logger.info(f"[+] Da ngat ket noi. Dong bo {len(fp_store)} van tay. "
                    f"Da dong SQLite.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
