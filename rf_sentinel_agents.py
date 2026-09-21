#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RF SENTINEL — AGENT LAYER
================================================================================
Implements the 6 agents described by the operator, wired into
SDR-BLUE-TEAM.py via dependency injection (same pattern rf_sentinel_ui.py
already uses for Flask routes) so this file never imports the host module
directly — no circular imports, easy to unit test in isolation.

  1. Self-Organizing Map (SOM)              -> SimpleSOM
  2. Teacher-Student architecture           -> TeacherStudentBridge
  3. Cognitive Frequency Agent              -> CognitiveFrequencyAgent
  4. Dataset & Active-Learning Agent        -> ActiveLearningAgent
  5. Automated Response / Isolation Agent   -> AutomatedResponseAgent
  6. Protocol Decoder Agent                 -> ProtocolDecoderAgent
  (+) Single-station AoA/RSSI bearing helper -> BearingEstimator

All of it is orchestrated by `AgentSuite`, the single object SDR-BLUE-TEAM.py
constructs and calls into.

--------------------------------------------------------------------------------
SCOPE / SAFETY NOTE — read this before extending anything below
--------------------------------------------------------------------------------
This module is receive-side decision support ONLY:
  * It reads IQ snapshots the host has already captured (RX).
  * It may adjust RX gain (lna_gain/vga_gain) — not TX power.
  * "Automated Response" means: send an alert (webhook/PDF/JSON), write
    evidence to disk, and — ONLY if the operator explicitly configures
    RESPONSE_ACTION_SCRIPT — shell out to a script THE OPERATOR PROVIDES.
    This file contains no jamming, deauth, spoofing, exploitation, or
    packet-injection code, and never will; it only ever *calls out* to
    infrastructure the operator already owns and has authorized.
  * ProtocolDecoderAgent only demodulates/decodes what was already
    received; it never keys a transmitter.
Every SDR handle this module ever touches is expected to already be the
host's `ReceiveOnlySDRProxy` — if it isn't, gain calls will simply fail
closed (caught and logged), same as everything else in this file.
================================================================================
"""

from __future__ import annotations

import io
import json
import logging
import math
import os
import shutil
import struct
import subprocess
import sys
import threading
import time
import traceback
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# report_error — project rule: NO SILENT FAILURES.  An `except` block must
# re-raise or call this (or log at WARNING+); never `pass`, never a bare
# fallback, never logger.debug.  Byte-identical copy of the one in
# SDR-BLUE-TEAM.py (this file must stay importable on its own); a test
# asserts the copies match.  See that file for the full contract of `every`.
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


def _emit(logger, tag, msg, level="info"):
    """Log through `logger` when there is one.  With NO logger, warning and
    above go to stderr instead of vanishing (info/debug chatter may stay quiet)."""
    text = f"[{tag}] {msg}"
    if logger:
        getattr(logger, level, logger.info)(text)
    elif level in ("warning", "error", "critical"):
        print(text, file=sys.stderr)


def _spawn_logged(cmd, log_path, what, stdin_bytes=None):
    """Fire-and-forget a child process WITHOUT going blind on it: its
    stdout+stderr are appended to `log_path` (was DEVNULL, so a crashing script
    left no trace) and a watcher thread reports any non-zero exit code."""
    with open(log_path, "ab") as logfh:
        p = subprocess.Popen(
            cmd, stdin=subprocess.PIPE if stdin_bytes is not None else None,
            stdout=logfh, stderr=subprocess.STDOUT)
    if stdin_bytes is not None:
        p.stdin.write(stdin_bytes)
        p.stdin.close()

    def _watch():
        rc = p.wait()
        if rc != 0:
            report_error(f"{what} exit={rc}",
                         f"script thoat voi ma {rc} - xem {log_path}", every=0)
    threading.Thread(target=_watch, daemon=True, name=f"watch-{what}").start()
    return p


# ---------------------------------------------------------------------------
# Soft dependencies — mirror the host's _dyn_import philosophy: never crash
# this module just because an optional package is missing — but say so.
# ---------------------------------------------------------------------------
def _try_import(name, attr=None):
    try:
        import importlib
        mod = importlib.import_module(name)
        return getattr(mod, attr) if attr else mod
    except Exception as e:
        report_error(f"DEP {name}", e, every=None, level="warning")
        return None

np = _try_import("numpy")
if np is None:
    raise ImportError("numpy la bat buoc cho rf_sentinel_agents.py")

_requests           = _try_import("requests")
matplotlib          = _try_import("matplotlib")
_reportlab_canvas    = _try_import("reportlab.pdfgen.canvas", "Canvas")
_reportlab_pagesizes = _try_import("reportlab.lib.pagesizes", "A4")
_scipy_signal        = _try_import("scipy.signal")

MATPLOTLIB_OK = matplotlib is not None
REPORTLAB_OK  = _reportlab_canvas is not None and _reportlab_pagesizes is not None
SCIPY_OK      = _scipy_signal is not None

if MATPLOTLIB_OK:
    try:
        matplotlib.use("Agg")  # headless — never try to open a GUI window
        import matplotlib.pyplot as plt
    except Exception as e:
        report_error("matplotlib backend/pyplot", e, every=None, level="warning")
        MATPLOTLIB_OK = False

import urllib.request
import urllib.error
import urllib.parse


# ============================================================================
# SMALL SHARED HELPERS
# ============================================================================
def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")


def _to_dict(obj):
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    if is_dataclass(obj):
        return asdict(obj)
    return dict(getattr(obj, "__dict__", {}))


def _safe_float(x, default=0.0):
    if x is None:                      # explicit "no value" is normal, not an error
        return default
    try:
        v = float(x)
        return v if math.isfinite(v) else default
    except Exception as e:
        report_error("_safe_float",
                     f"{type(e).__name__}: {e} (gia tri={x!r:.60})", every=60, level="warning")
        return default


# ============================================================================
# 1) SELF-ORGANIZING MAP (SOM)
# ----------------------------------------------------------------------------
# From-scratch, numpy-only SOM (no extra dependency). Maps the multi-
# dimensional signal-feature vector (power, entropy, kurtosis, cyclo, FHSS,
# ...) down to a 2D grid. Strange signals get pushed to the rim of the map
# by construction (they're far from every trained-on-normal neuron), so the
# AI can gate on "how far from the trained center is this cell" without
# ever needing a name for the waveform.
# ============================================================================
class SimpleSOM:
    def __init__(self, grid_w: int = 10, grid_h: int = 10, dim: int = 8,
                 lr: float = 0.35, seed: int = 42):
        self.w, self.h, self.dim = grid_w, grid_h, dim
        self.lr0 = lr
        rng = np.random.default_rng(seed)
        self.weights = rng.normal(0.0, 0.3, size=(grid_w, grid_h, dim)).astype(np.float32)
        self._trained_samples = 0
        # grid coordinate cache for BMU distance-to-edge normalisation
        cx, cy = (grid_w - 1) / 2.0, (grid_h - 1) / 2.0
        self._center = np.array([cx, cy], dtype=np.float32)
        self._max_radius = math.hypot(max(cx, grid_w - 1 - cx),
                                       max(cy, grid_h - 1 - cy)) or 1.0
        self._lock = threading.Lock()
        # Hit-count grid — every bmu() lookup (normal or alerted) leaves a
        # mark here, purely for visualization (see /api/agents/som/grid).
        # Does not affect training at all.
        self._hits = np.zeros((grid_w, grid_h), dtype=np.int64)

    def _bmu_index(self, vec: np.ndarray):
        diff = self.weights - vec.reshape(1, 1, -1)
        d2 = np.einsum("ijk,ijk->ij", diff, diff)
        idx = np.unravel_index(int(np.argmin(d2)), d2.shape)
        return idx  # (x, y)

    def observe(self, vec: np.ndarray, epoch_hint: Optional[int] = None):
        """One online SOM update step (unsupervised — call this on every
        normal-looking sample so the map keeps representing 'what's usual
        here'). Alert-flagged samples should call bmu()/edge_score() only,
        never observe(), so anomalies never get absorbed into the map."""
        vec = np.asarray(vec, dtype=np.float32).reshape(-1)
        if vec.shape[0] != self.dim:
            return
        with self._lock:
            self._trained_samples += 1
            t = epoch_hint if epoch_hint is not None else self._trained_samples
            lr = self.lr0 * math.exp(-t / 4000.0)
            sigma = max(1.0, (max(self.w, self.h) / 2.0) * math.exp(-t / 4000.0))

            bx, by = self._bmu_index(vec)
            self._hits[bx, by] += 1
            xs, ys = np.meshgrid(np.arange(self.w), np.arange(self.h), indexing="ij")
            dist2 = (xs - bx) ** 2 + (ys - by) ** 2
            neigh = np.exp(-dist2 / (2.0 * sigma * sigma)).astype(np.float32)
            self.weights += (lr * neigh)[:, :, None] * (vec.reshape(1, 1, -1) - self.weights)

    def bmu(self, vec: np.ndarray, record_hit: bool = True):
        vec = np.asarray(vec, dtype=np.float32).reshape(-1)
        if vec.shape[0] != self.dim:
            return (self.w // 2, self.h // 2)
        with self._lock:
            bx, by = self._bmu_index(vec)
            if record_hit:
                self._hits[bx, by] += 1
            return bx, by

    def edge_score(self, vec: np.ndarray) -> float:
        """0.0 = lands at the trained center of the map, 1.0 = pinned to the
        rim/corner. Strange signals cluster near 1.0 with no label needed."""
        bx, by = self.bmu(vec)
        r = math.hypot(bx - self._center[0], by - self._center[1])
        return float(min(1.0, r / self._max_radius))

    def snapshot(self) -> dict:
        """Lightweight JSON-able view for the /api/agents/som endpoint —
        the BMU density grid (how the map currently looks), not the raw
        weight tensor."""
        with self._lock:
            return {
                "grid_w": self.w, "grid_h": self.h,
                "trained_samples": self._trained_samples,
                "density": self._hits.tolist(),
            }


def _feature_vector(anomaly) -> np.ndarray:
    """Build the 8-dim feature vector fed to the SOM from an
    EW_AnomalyResult (or its dict form)."""
    d = _to_dict(anomaly)
    return np.array([
        _safe_float(d.get("zscore")) / 6.0,
        _safe_float(d.get("entropy")),
        min(1.0, _safe_float(d.get("kurtosis")) / 20.0),
        _safe_float(d.get("sample_entropy")),
        _safe_float(d.get("stft_entropy")),
        _safe_float(d.get("cyclo_score")),
        _safe_float(d.get("dtw_fhss_score")),
        _safe_float(d.get("cyclo_adv_score")),
    ], dtype=np.float32)


# ============================================================================
# SIGMF WRITER  —  minimal but spec-shaped .sigmf-data / .sigmf-meta pair
# https://github.com/sigmf/SigMF  (core namespace only; good enough for a
# human/teacher to open the capture with any SigMF-aware tool).
# ============================================================================
def write_sigmf(iq: "np.ndarray", sample_rate: float, freq_hz: float,
                 base_path: str, extra_meta: Optional[dict] = None):
    """iq: complex64 array (already RX-side, never re-transmitted).
    Writes base_path + '.sigmf-data' (raw ci8) and '.sigmf-meta' (JSON).
    Returns (data_path, meta_path) — either may be None on failure."""
    data_path = base_path + ".sigmf-data"
    meta_path = base_path + ".sigmf-meta"
    try:
        if iq is not None and len(iq):
            iq8 = np.clip(np.round(np.stack([iq.real, iq.imag], axis=-1)),
                          -127, 127).astype(np.int8)
            iq8.tofile(data_path)
        else:
            data_path = None
    except Exception as e:
        report_error("write_sigmf data", e, every=0)
        data_path = None

    meta = {
        "global": {
            "core:datatype": "ci8",
            "core:sample_rate": float(sample_rate),
            "core:version": "1.0.0",
            "core:recorder": "rf_sentinel_agents.ActiveLearningAgent",
            "core:description": "Low-confidence capture auto-queued for review.",
        },
        "captures": [{
            "core:sample_start": 0,
            "core:frequency": float(freq_hz),
            "core:datetime": _now_iso(),
        }],
        "annotations": [],
    }
    if extra_meta:
        meta["global"]["sentinel:extra"] = extra_meta
    try:
        with open(meta_path, "w") as fh:
            json.dump(meta, fh, indent=2, default=str)
    except Exception as e:
        report_error("write_sigmf meta", e, every=0)
        meta_path = None
    return data_path, meta_path


# ============================================================================
# 3) COGNITIVE FREQUENCY AGENT
# ----------------------------------------------------------------------------
# Keeps the scanner from going "blind": watches for ADC clipping (too much
# gain -> saturation) and for dead air (too little gain -> buried in the
# noise floor), and nudges RX gain within safe bounds. Also tracks which
# watchlist channel is showing the strongest FHSS/hopping signature so the
# caller can choose to dwell there longer next round.
# ============================================================================
class CognitiveFrequencyAgent:
    CLIP_HIGH        = 0.02   # >2% of I/Q samples near full-scale -> back off
    CLIP_LOW_POWER    = -95.0  # dBm-ish floor below which we consider "blind"
    GAIN_STEP         = 8
    LNA_MIN, LNA_MAX  = 0, 40
    VGA_MIN, VGA_MAX  = 0, 62

    def __init__(self, logger=None):
        self.logger = logger
        self._last_adjust = defaultdict(float)   # per-channel cooldown
        self._cooldown_s = 5.0
        self._fhss_scores: dict = {}

    def _log(self, msg, level="info"):
        _emit(self.logger, "FREQ-AGENT", msg, level)

    @staticmethod
    def clip_fraction(iq: "np.ndarray") -> float:
        if iq is None or len(iq) == 0:
            return 0.0
        near_full = (np.abs(iq.real) >= 126) | (np.abs(iq.imag) >= 126)
        return float(np.mean(near_full))

    def maybe_adjust_gain(self, sdr_proxy, iq, channel_name: str,
                          power_dbm: float) -> Optional[str]:
        """Best-effort RX gain nudge. Never touches anything transmit-
        related — only lna_gain/vga_gain, exactly like connect_hackrf()
        already does at startup. Rate-limited per channel so it doesn't
        fight the AGC every single sweep round."""
        if sdr_proxy is None:
            return None
        now = time.time()
        if now - self._last_adjust[channel_name] < self._cooldown_s:
            return None

        clip = self.clip_fraction(iq)
        action = None
        try:
            if clip > self.CLIP_HIGH:
                cur = getattr(sdr_proxy, "vga_gain", None)
                if cur is not None:
                    new = max(self.VGA_MIN, int(cur) - self.GAIN_STEP)
                    if new != cur:
                        sdr_proxy.vga_gain = new
                        action = f"clip={clip:.1%} tren {channel_name} -> giam VGA gain {cur}->{new}"
            elif power_dbm < self.CLIP_LOW_POWER:
                cur = getattr(sdr_proxy, "vga_gain", None)
                if cur is not None:
                    new = min(self.VGA_MAX, int(cur) + self.GAIN_STEP)
                    if new != cur:
                        sdr_proxy.vga_gain = new
                        action = f"tin hieu yeu ({power_dbm:.1f}dBm) tren {channel_name} -> tang VGA gain {cur}->{new}"
        except Exception as e:
            report_error("CognitiveFrequencyAgent.maybe_adjust_gain", e)
            return None

        if action:
            self._last_adjust[channel_name] = now
            self._log(action)
        return action

    def note_fhss(self, channel_name: str, dtw_score: float):
        self._fhss_scores[channel_name] = dtw_score

    def suggest_focus(self, threshold: float = 0.6) -> Optional[str]:
        """Which channel (if any) is showing the strongest hop-pattern
        activity right now and deserves extra dwell time next round."""
        if not self._fhss_scores:
            return None
        name, score = max(self._fhss_scores.items(), key=lambda kv: kv[1])
        return name if score >= threshold else None


# ============================================================================
# 4) DATASET & ACTIVE-LEARNING AGENT
# ----------------------------------------------------------------------------
# `confidence` in this codebase is an *anomaly score* (high = strange),
# not a certainty score.  We want to queue the samples a human label would
# be most valuable for: ones that scored high enough to be interesting but
# haven't been confirmed yet.  That means enqueueing when
#   confidence >= CONF_THRESHOLD   (anomalous / uncertain)
# and *ignoring* low-scoring samples that are almost certainly clean noise.
#
# Bug present in original code: `< CONF_THRESHOLD` queued the boring
# low-anomaly majority, which caused queue.json to balloon (≈66 KB per
# entry, rewritten in full on every append) while missing the rare
# high-anomaly events that actually need a human label.
#
# Every time a high-confidence capture arrives, snip the IQ, write it as a
# .sigmf pair, and add it to a human-in-the-loop labeling queue (JSON-backed
# — trivial to inspect/back up, no extra DB dependency). Periodically kicks
# off a retrain of the supervised layer.
# ============================================================================
class ActiveLearningAgent:
    CONF_THRESHOLD    = 0.60
    RETRAIN_EVERY_NEW = 50     # newly-labeled items since last retrain

    def __init__(self, base_dir: str, logger=None,
                 retrain_script: Optional[str] = None,
                 db_insert_labeled_fn: Optional[Callable] = None):
        self.dir = os.path.join(base_dir, "active_learning")
        os.makedirs(self.dir, exist_ok=True)
        self.queue_path = os.path.join(self.dir, "queue.json")
        self.logger = logger
        self.retrain_script = retrain_script or os.environ.get("RF_RETRAIN_SCRIPT")
        # Injected the same way rf_sentinel_ui's routes are — lets a human/
        # teacher label feed straight back into the host's own `events`
        # table (confirmed=1, threat_type=label) so RFThreatClassifier.train()
        # actually sees it. Optional: without it, labels just sit in
        # queue.json for manual/offline use.
        self.db_insert_labeled_fn = db_insert_labeled_fn
        self._lock = threading.Lock()
        self._labeled_since_retrain = 0
        self._queue = self._load()

    def _log(self, msg, level="info"):
        _emit(self.logger, "ACTIVE-LEARN", msg, level)

    def _load(self):
        if not os.path.isfile(self.queue_path):
            return []                    # first run: no queue yet — normal, not an error
        try:
            with open(self.queue_path, "r") as fh:
                return json.load(fh)
        except Exception as e:
            # Unreadable/corrupt queue.  Returning [] here and letting the next
            # _save() overwrite the file would silently destroy the analyst's
            # labelled data — so shout, and keep a copy of the bad file first.
            report_error("ActiveLearningAgent._load queue.json", e, every=0)
            try:
                keep = f"{self.queue_path}.corrupt-{_stamp()}"
                shutil.copy2(self.queue_path, keep)
                report_error("ActiveLearningAgent._load backup",
                             f"ban sao file hong giu tai {keep}", every=0, level="warning")
            except Exception as e2:
                report_error("ActiveLearningAgent._load backup", e2, every=0)
            return []

    def _save(self):
        try:
            with open(self.queue_path, "w") as fh:
                json.dump(self._queue, fh, indent=2, default=str)
        except Exception as e:
            self._log(f"khong ghi duoc queue: {e}", "warning")

    def should_enqueue(self, confidence: float) -> bool:
        # confidence is an anomaly score (high = strange).  Queue samples
        # that are *above* threshold — they are the ones worth a human label.
        # Samples below threshold are likely clean noise and are not worth
        # storing; leaving them out also keeps queue.json small.
        return confidence >= self.CONF_THRESHOLD

    def enqueue(self, result, iq, sample_rate: float,
                persistence_ratio: float = 0.0) -> Optional[str]:
        with self._lock:
            entry_id = uuid.uuid4().hex[:12]
            base = os.path.join(self.dir, f"{_stamp()}_{entry_id}")
            data_path, meta_path = write_sigmf(
                iq, sample_rate, getattr(result, "freq_hz", 0.0), base,
                extra_meta={"channel": getattr(result, "channel", ""),
                            "threat_type": getattr(result, "threat_type", "")})
            # Keep the full feature snapshot so a later label can be
            # replayed straight into the training table without needing
            # the original IQ or a live sweep round.
            metrics = _to_dict(getattr(result, "anomaly", None))
            entry = {
                "id": entry_id,
                "created_at": _now_iso(),
                "channel": getattr(result, "channel", ""),
                "freq_hz": getattr(result, "freq_hz", 0.0),
                "threat_type": getattr(result, "threat_type", ""),
                "confidence": _safe_float(getattr(result, "confidence", 0.0)),
                "persistence_ratio": _safe_float(persistence_ratio),
                "metrics": metrics,
                "sigmf_data": data_path,
                "sigmf_meta": meta_path,
                "status": "pending",       # pending | labeled | discarded
                "label": None,
                "labeled_by": None,
                "labeled_at": None,
            }
            self._queue.append(entry)
            self._save()
            self._log(f"queued {entry_id} ({entry['channel']}, "
                      f"conf={entry['confidence']:.2f}) cho human review")
            return entry_id

    def list_queue(self, status: Optional[str] = None, limit: int = 200):
        with self._lock:
            items = self._queue
            if status:
                items = [i for i in items if i.get("status") == status]
            return list(reversed(items))[:limit]

    def label(self, entry_id: str, label: str, labeled_by: str = "analyst") -> bool:
        with self._lock:
            for e in self._queue:
                if e["id"] == entry_id:
                    e["status"] = "labeled"
                    e["label"] = label
                    e["labeled_by"] = labeled_by
                    e["labeled_at"] = _now_iso()
                    self._labeled_since_retrain += 1
                    self._save()
                    self._log(f"{entry_id} da duoc gan nhan '{label}' boi {labeled_by}")
                    if self.db_insert_labeled_fn is not None:
                        try:
                            self.db_insert_labeled_fn(e, label)
                        except Exception as ex:
                            self._log(f"khong ghi duoc nhan vao events DB: {ex}",
                                      "warning")
                    return True
            return False

    def discard(self, entry_id: str) -> bool:
        with self._lock:
            for e in self._queue:
                if e["id"] == entry_id:
                    e["status"] = "discarded"
                    self._save()
                    return True
            return False

    def maybe_retrain(self, get_rf_fn: Optional[Callable] = None):
        """Fire a retrain either via an external script (if configured) or
        by calling the host's own RFThreatClassifier.train() through the
        injected get_rf_fn(). Threshold-gated so this doesn't hammer the
        trainer on every single label."""
        if self._labeled_since_retrain < self.RETRAIN_EVERY_NEW:
            return
        self._labeled_since_retrain = 0
        if self.retrain_script and os.path.isfile(self.retrain_script):
            try:
                _spawn_logged(["python3", self.retrain_script],
                              os.path.join(self.dir, "retrain_script.log"), "retrain script")
                self._log(f"da goi retrain script: {self.retrain_script}")
                return
            except Exception as e:
                self._log(f"khong chay duoc retrain script: {e}", "warning")
        if get_rf_fn is not None:
            try:
                rf = get_rf_fn()
                if rf is not None and hasattr(rf, "train"):
                    rf.train()
                    self._log("da goi RFThreatClassifier.train()")
            except Exception as e:
                self._log(f"retrain noi bo loi: {e}", "warning")


# ============================================================================
# 2) TEACHER-STUDENT ARCHITECTURE
# ----------------------------------------------------------------------------
# "Student" = the host's existing RFThreatClassifier (LightGBM-backed when
# available), running every sweep round — fast, low RAM, on-device.
# When the Student is unsure (confidence < threshold) it does NOT ask a
# human directly — it packages the capture as .sigmf (via
# ActiveLearningAgent) and, if a Teacher endpoint is configured, ships the
# metadata to it for a second opinion. No raw IQ leaves the box unless the
# operator explicitly points TEACHER_ENDPOINT somewhere and accepts that.
# ============================================================================
class TeacherStudentBridge:
    def __init__(self, active_learning: ActiveLearningAgent,
                 endpoint: Optional[str] = None, logger=None,
                 send_raw_iq: bool = False, timeout_s: float = 4.0):
        self.al = active_learning
        self.endpoint = endpoint or os.environ.get("TEACHER_ENDPOINT")
        self.logger = logger
        self.send_raw_iq = send_raw_iq
        self.timeout_s = timeout_s

    def _log(self, msg, level="info"):
        _emit(self.logger, "TEACHER-STUDENT", msg, level)

    def maybe_escalate(self, result, iq, sample_rate: float, entry_id: Optional[str]):
        """Call this AFTER ActiveLearningAgent.enqueue() so entry_id and the
        .sigmf files already exist. Fires a background thread — never
        blocks the sweep loop on network I/O."""
        if not self.endpoint or entry_id is None:
            return
        t = threading.Thread(target=self._ask_teacher,
                             args=(result, iq, sample_rate, entry_id), daemon=True)
        t.start()

    def _ask_teacher(self, result, iq, sample_rate, entry_id):
        payload = {
            "entry_id": entry_id,
            "channel": getattr(result, "channel", ""),
            "freq_hz": getattr(result, "freq_hz", 0.0),
            "threat_type": getattr(result, "threat_type", ""),
            "confidence": _safe_float(getattr(result, "confidence", 0.0)),
            "sample_rate": sample_rate,
            "metrics": _to_dict(getattr(result, "anomaly", None)),
        }
        if self.send_raw_iq and iq is not None and len(iq):
            # Only ever included if the operator explicitly opted in.
            payload["iq_re"] = np.real(iq).astype(float).round(2).tolist()
            payload["iq_im"] = np.imag(iq).astype(float).round(2).tolist()
        try:
            req = urllib.request.Request(
                self.endpoint, data=json.dumps(payload, default=str).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
                body = json.loads(resp.read().decode("utf-8", "replace"))
            label = body.get("label")
            conf  = _safe_float(body.get("confidence", 0.0))
            if label:
                self.al.label(entry_id, label, labeled_by=f"teacher:{conf:.2f}")
                self._log(f"teacher tra loi cho {entry_id}: {label} ({conf:.2f})")
        except urllib.error.URLError as e:
            report_error("TeacherStudent endpoint unreachable", e, every=60, level="warning")
        except Exception as e:
            report_error("TeacherStudent._ask_teacher", e)


# ============================================================================
# 5) AUTOMATED RESPONSE / ISOLATION AGENT  ("SOC Tier-1 analyst")
# ----------------------------------------------------------------------------
# Real-time webhook alerts + PDF/JSON incident reports with a waterfall
# chart and the .sigmf/.iq sample bundled for forensics. For confirmed
# wireless-attack signatures (deauth/jamming), it can optionally shell out
# to an operator-supplied response script — this file supplies no attack
# or block logic of its own, only the hand-off.
# ============================================================================
class AutomatedResponseAgent:
    def __init__(self, base_dir: str, logger=None,
                 webhooks: Optional[dict] = None,
                 response_script: Optional[str] = None,
                 min_level_value: int = 3):   # ThreatLevel.HIGH == 3 in host enum
        self.dir = os.path.join(base_dir, "incidents")
        os.makedirs(self.dir, exist_ok=True)
        self.logger = logger
        self.webhooks = webhooks or self._webhooks_from_env()
        self.response_script = response_script or os.environ.get("RF_RESPONSE_SCRIPT")
        self.min_level_value = min_level_value
        self._jam_types = {"CELL_JAM", "GPS_JAM", "WIFI_DEAUTH", "DRONE_FHSS"}

    def _log(self, msg, level="info"):
        _emit(self.logger, "RESPONSE-AGENT", msg, level)

    @staticmethod
    def _webhooks_from_env():
        out = {}
        # Supported webhooks: Telegram, Discord, Slack.
        # PagerDuty removed — this is a personal/self-hosted tool; no PD account.
        for key, env in (("telegram", "RF_WEBHOOK_TELEGRAM"),
                         ("discord", "RF_WEBHOOK_DISCORD"),
                         ("slack", "RF_WEBHOOK_SLACK")):
            v = os.environ.get(env)
            if v:
                out[key] = v
        return out

    # -------------------------------------------------------------- webhooks
    def _post_json(self, url: str, body: dict, timeout=5.0) -> bool:
        try:
            req = urllib.request.Request(
                url, data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return 200 <= resp.status < 300
        except Exception as e:
            self._log(f"webhook that bai ({url[:40]}...): {e}", "warning")
            return False

    def _fire_webhooks(self, result, summary: str):
        text = (f"[{getattr(result.threat_level, 'name', result.threat_level)}] "
               f"{summary}")
        for kind, url in self.webhooks.items():
            if kind == "discord":
                self._post_json(url, {"content": text})
            elif kind == "slack":
                self._post_json(url, {"text": text})
            elif kind == "telegram":
                # RF_WEBHOOK_TELEGRAM must be a full
                # https://api.telegram.org/bot<token>/sendMessage?chat_id=..
                # URL — we append the text parameter.
                sep = "&" if "?" in url else "?"
                self._post_json(url + f"{sep}text={urllib.parse.quote(text)}", {})

    # --------------------------------------------------------- waterfall PNG
    def _make_waterfall_png(self, iq, sample_rate: float, out_path: str) -> Optional[str]:
        if not (MATPLOTLIB_OK and SCIPY_OK) or iq is None or len(iq) < 256:
            return None
        try:
            f, t, Sxx = _scipy_signal.spectrogram(
                iq, fs=sample_rate, nperseg=min(256, len(iq)), return_onesided=False)
            Sxx_db = 10 * np.log10(np.maximum(Sxx, 1e-12))
            fig, ax = plt.subplots(figsize=(6, 3), dpi=110)
            ax.pcolormesh(t, np.fft.fftshift(f) / 1e3, np.fft.fftshift(Sxx_db, axes=0),
                         shading="auto", cmap="viridis")
            ax.set_ylabel("kHz offset")
            ax.set_xlabel("s")
            ax.set_title("Waterfall")
            fig.tight_layout()
            fig.savefig(out_path)
            plt.close(fig)
            return out_path
        except Exception as e:
            report_error("AutomatedResponseAgent._make_waterfall_png", e)
            return None

    # ------------------------------------------------------------- PDF/JSON
    def _make_report(self, result, meta: dict, waterfall_png: Optional[str],
                     base: str) -> dict:
        json_path = base + ".json"
        with open(json_path, "w") as fh:
            json.dump(meta, fh, indent=2, default=str)

        pdf_path = None
        if REPORTLAB_OK:
            pdf_path = base + ".pdf"
            try:
                c = _reportlab_canvas(pdf_path, pagesize=_reportlab_pagesizes)
                w, h = _reportlab_pagesizes
                y = h - 50
                c.setFont("Helvetica-Bold", 14)
                c.drawString(40, y, "RF SENTINEL — INCIDENT REPORT")
                y -= 24
                c.setFont("Helvetica", 10)
                for line in (
                    f"Thoi gian: {meta.get('timestamp')}",
                    f"Kenh: {meta.get('channel')} @ {meta.get('freq_hz', 0)/1e6:.3f} MHz",
                    f"Muc do: {meta.get('severity')}",
                    f"Loai: {meta.get('threat_type')}",
                    f"Do tin cay: {meta.get('confidence')}",
                ):
                    c.drawString(40, y, line)
                    y -= 16
                y -= 8
                c.setFont("Helvetica-Bold", 11)
                c.drawString(40, y, "Dau hieu:")
                y -= 16
                c.setFont("Helvetica", 9)
                for ind in meta.get("indicators", [])[:20]:
                    c.drawString(50, y, f"- {ind}"[:110])
                    y -= 13
                    if y < 120:
                        break
                if waterfall_png and os.path.isfile(waterfall_png):
                    try:
                        c.drawImage(waterfall_png, 40, max(60, y - 220),
                                   width=w - 80, preserveAspectRatio=True)
                    except Exception as e:
                        report_error("_make_report drawImage", e, every=0, level="warning")
                c.showPage()
                c.save()
            except Exception as e:
                self._log(f"khong tao duoc PDF: {e}", "warning")
                pdf_path = None
        return {"json": json_path, "pdf": pdf_path}

    # --------------------------------------------------------------- action
    def _maybe_call_response_script(self, result, meta: dict):
        threat_type = getattr(result, "threat_type", "")
        if threat_type not in self._jam_types:
            return
        if not self.response_script:
            self._log(f"phat hien {threat_type} nhung khong co "
                      f"RF_RESPONSE_SCRIPT duoc cau hinh — chi ghi log, "
                      f"khong hanh dong.", "warning")
            return
        if not os.path.isfile(self.response_script):
            self._log(f"RF_RESPONSE_SCRIPT khong ton tai: {self.response_script}", "warning")
            return
        try:
            _spawn_logged(["python3", self.response_script],
                          os.path.join(self.dir, "response_script.log"), "response script",
                          stdin_bytes=json.dumps(meta, default=str).encode("utf-8"))
            self._log(f"da goi response script cho {threat_type}: {self.response_script}")
        except Exception as e:
            self._log(f"khong chay duoc response script: {e}", "warning")

    # ---------------------------------------------------------------- entry
    def handle(self, result, iq, sample_rate: float, iq_evidence_path: Optional[str] = None,
              sigmf_paths=None):
        lvl = getattr(result, "threat_level", None)
        lvl_value = getattr(lvl, "value", 0)
        if lvl_value < self.min_level_value:
            return None

        base = os.path.join(self.dir, f"{_stamp()}_{getattr(result, 'channel', 'ch')}")
        waterfall = self._make_waterfall_png(iq, sample_rate, base + "_waterfall.png")

        meta = {
            "timestamp": getattr(result, "timestamp", _now_iso()),
            "channel": getattr(result, "channel", ""),
            "freq_hz": getattr(result, "freq_hz", 0.0),
            "threat_type": getattr(result, "threat_type", ""),
            "severity": getattr(lvl, "name", str(lvl)),
            "confidence": _safe_float(getattr(result, "confidence", 0.0)),
            "rf_label": getattr(result, "rf_label", None),
            "rf_confidence": _safe_float(getattr(result, "rf_confidence", 0.0)),
            "indicators": getattr(result, "indicators", []),
            "action": getattr(result, "action", ""),
            "iq_evidence_path": iq_evidence_path,
            "sigmf": sigmf_paths,
            "waterfall_png": waterfall,
        }
        paths = self._make_report(result, meta, waterfall, base)
        summary = (f"{meta['channel']} @ {meta['freq_hz']/1e6:.3f} MHz — "
                  f"{meta['threat_type']} (conf={meta['confidence']:.2f})")
        self._fire_webhooks(result, summary)
        self._maybe_call_response_script(result, meta)
        return {"meta": meta, "paths": paths}


# ============================================================================
# 6) PROTOCOL DECODER AGENT
# ----------------------------------------------------------------------------
# Best-effort passive decode of the IQ that was already captured. Prefers
# shelling out to `rtl_433` (file-replay mode, if the binary is on PATH) so
# it benefits from that project's large protocol library; otherwise falls
# back to a simple envelope/OOK pulse-timing summary using numpy/scipy
# alone. This never transmits anything — it only reads bytes already sitting
# in the `iq` array the sweep loop handed it.
# ============================================================================
class ProtocolDecoderAgent:
    ISM_TYPES = {"IOT_REPLAY", "LORA_SKIM"}

    def __init__(self, base_dir: str, logger=None):
        self.dir = os.path.join(base_dir, "decoded")
        os.makedirs(self.dir, exist_ok=True)
        self.logger = logger
        self._rtl_433_path = self._which("rtl_433")

    def _log(self, msg, level="info"):
        _emit(self.logger, "DECODER", msg, level)

    @staticmethod
    def _which(binary: str) -> Optional[str]:
        for p in os.environ.get("PATH", "").split(os.pathsep):
            cand = os.path.join(p, binary)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
        return None

    def should_decode(self, threat_type: str) -> bool:
        return threat_type in self.ISM_TYPES

    def decode(self, iq, sample_rate: float, freq_hz: float, channel_name: str) -> Optional[dict]:
        if iq is None or len(iq) == 0:
            return None
        if self._rtl_433_path:
            result = self._decode_via_rtl433(iq, sample_rate, freq_hz)
            if result is not None:
                return result
        return self._decode_ook_fallback(iq, sample_rate, channel_name)

    # --------------------------------------------------------- rtl_433 path
    def _decode_via_rtl433(self, iq, sample_rate, freq_hz) -> Optional[dict]:
        """rtl_433 file-replay mode: -r <cu8 file> reads pre-captured
        samples, never touches a transmitter. cu8 = unsigned 8-bit
        interleaved I/Q (rtl_433's on-disk convention)."""
        try:
            cu8 = np.clip(np.round(
                np.stack([iq.real, iq.imag], axis=-1) + 127.0), 0, 255).astype(np.uint8)
            tmp_path = os.path.join(self.dir, f"_tmp_{uuid.uuid4().hex[:8]}.cu8")
            cu8.tofile(tmp_path)
            cmd = [self._rtl_433_path, "-r", tmp_path,
                  "-s", str(int(sample_rate)), "-f", str(int(freq_hz)),
                  "-F", "json"]
            out = subprocess.run(cmd, capture_output=True, timeout=10, text=True)
            if out.returncode != 0:
                # Used to be ignored: a crashing rtl_433 just looked like "no packets".
                report_error("rtl_433 exit code",
                             f"rtl_433 thoat voi ma {out.returncode}: "
                             f"{(out.stderr or '').strip()[:200]!r}", every=60, level="warning")
            try:
                os.remove(tmp_path)
            except Exception as e:
                report_error("rtl_433 tmp cleanup", e, every=60, level="warning")
            lines = [l for l in out.stdout.splitlines() if l.strip().startswith("{")]
            decoded = [json.loads(l) for l in lines]
            if decoded:
                self._log(f"rtl_433 giai ma duoc {len(decoded)} goi tin")
                return {"decoder": "rtl_433", "packets": decoded}
            return None
        except Exception as e:
            report_error("ProtocolDecoder._decode_via_rtl433", e)
            return None

    # -------------------------------------------------------------- fallback
    def _decode_ook_fallback(self, iq, sample_rate, channel_name) -> dict:
        """Crude AM-envelope OOK/ASK pulse-timing summary — enough to flag
        'this looks like a keyfob/sensor burst' without any external tool."""
        env = np.abs(iq).astype(np.float32)
        if env.max() <= 0:
            return {"decoder": "ook_fallback", "pulses": 0}
        thresh = 0.5 * (env.max() + np.median(env))
        on = env > thresh
        edges = np.diff(on.astype(np.int8))
        rises = np.where(edges == 1)[0]
        falls = np.where(edges == -1)[0]
        n = min(len(rises), len(falls))
        widths_us = []
        for i in range(n):
            if falls[i] > rises[i]:
                widths_us.append((falls[i] - rises[i]) / sample_rate * 1e6)
        return {
            "decoder": "ook_fallback",
            "channel": channel_name,
            "pulses": n,
            "avg_pulse_width_us": round(float(np.mean(widths_us)), 1) if widths_us else None,
            "note": "cai dat rtl_433 tren PATH de giai ma day du protocol.",
        }


# ============================================================================
# AoA / RSSI SINGLE-STATION BEARING ESTIMATOR
# ----------------------------------------------------------------------------
# With one station you can't triangulate, but rotating a directional
# antenna and logging RSSI vs. heading gives a coarse bearing. This just
# stores (angle, rssi) samples per channel and returns the RSSI-weighted
# circular mean as the best-guess direction.
# ============================================================================
class BearingEstimator:
    def __init__(self, max_samples_per_channel: int = 360):
        self._samples = defaultdict(lambda: deque(maxlen=max_samples_per_channel))

    def add_sample(self, channel_name: str, angle_deg: float, rssi_dbm: float):
        self._samples[channel_name].append(
            (float(angle_deg) % 360.0, float(rssi_dbm)))

    def estimate(self, channel_name: str) -> Optional[dict]:
        samples = self._samples.get(channel_name)
        if not samples or len(samples) < 3:
            return None
        angles = np.array([a for a, _ in samples])
        rssi   = np.array([r for _, r in samples])
        w = rssi - rssi.min() + 1e-3   # linear weights, all positive
        rad = np.deg2rad(angles)
        x = float(np.sum(w * np.cos(rad)))
        y = float(np.sum(w * np.sin(rad)))
        bearing = math.degrees(math.atan2(y, x)) % 360.0
        confidence = float(min(1.0, (rssi.max() - rssi.min()) / 30.0))
        return {
            "channel": channel_name,
            "bearing_deg": round(bearing, 1),
            "confidence": round(confidence, 2),
            "n_samples": len(samples),
        }

    def clear(self, channel_name: str):
        self._samples.pop(channel_name, None)


# ============================================================================
# ORCHESTRATOR — AgentSuite
# ============================================================================
# ============================================================================
# /agents DASHBOARD — self-contained HTML/JS page (no build step, no extra
# dependency, matches the dark/monospace look of the fallback UI in
# SDR-BLUE-TEAM.py). Polls /api/agents/som and /api/agents/queue every few
# seconds. Label buttons POST to /api/agents/label.
# ============================================================================
_AGENTS_DASHBOARD_HTML = """<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<title>RF Sentinel — Agents</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: dark; }
  body { background:#0b0f14; color:#c9d6e3; font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
        margin:0; padding:20px; }
  h1 { color:#3eb8ff; font-size:1.3rem; margin:0 0 4px; }
  h2 { color:#7fd1ff; font-size:1rem; margin:28px 0 10px; border-bottom:1px solid #1c2733; padding-bottom:6px; }
  .sub { color:#6b7c8f; font-size:.85rem; margin-bottom:18px; }
  .grid-wrap { display:flex; gap:24px; flex-wrap:wrap; align-items:flex-start; }
  #som { image-rendering: pixelated; border:1px solid #1c2733; background:#000; }
  .legend { font-size:.8rem; color:#6b7c8f; }
  table { border-collapse:collapse; width:100%; font-size:.85rem; }
  th, td { text-align:left; padding:6px 8px; border-bottom:1px solid #1c2733; }
  th { color:#7fd1ff; font-weight:600; }
  tr:hover td { background:#111a24; }
  .badge { padding:2px 7px; border-radius:4px; font-size:.75rem; }
  .b-pending { background:#3a2f00; color:#ffcf4d; }
  .b-labeled { background:#0d3a1f; color:#4dffa0; }
  button { background:#132030; color:#c9d6e3; border:1px solid #2a3b4d; border-radius:4px;
          padding:4px 10px; margin-right:4px; cursor:pointer; font:inherit; font-size:.78rem; }
  button:hover { background:#1c3348; border-color:#3eb8ff; }
  .empty { color:#4a5a6b; font-style:italic; padding:14px 0; }
  .stat { display:inline-block; margin-right:22px; color:#8fa5ba; font-size:.85rem; }
  .stat b { color:#e6edf3; }
  input.label-input { background:#0b0f14; color:#c9d6e3; border:1px solid #2a3b4d; border-radius:4px;
                      padding:3px 6px; width:120px; font:inherit; font-size:.78rem; }
</style>
</head>
<body>
  <h1>RF Sentinel — Agent Layer</h1>
  <div class="sub">SOM map (rìa = lạ) · Active-Learning queue · tự làm mới mỗi 4s</div>

  <div id="stats"></div>

  <h2>Self-Organizing Map — mật độ tín hiệu bình thường + cảnh báo gần đây</h2>
  <div class="grid-wrap">
    <canvas id="som" width="300" height="300"></canvas>
    <div class="legend">
      <div>Ô sáng hơn = nhiều tín hiệu "bình thường" học được ở đó.</div>
      <div>Chấm đỏ = cảnh báo gần đây (di chuột để xem chi tiết).</div>
      <div style="margin-top:8px">Rìa/góc bản đồ = tín hiệu lạ, chưa từng thấy dạng đó.</div>
    </div>
  </div>

  <h2>Active-Learning Queue (chờ gắn nhãn)</h2>
  <table id="queue-table">
    <thead><tr><th>Channel</th><th>Freq (MHz)</th><th>Loại (đoán)</th><th>Conf</th><th>Trạng thái</th><th>Hành động</th></tr></thead>
    <tbody><tr><td colspan="6" class="empty">Đang tải...</td></tr></tbody>
  </table>

<script>
async function jget(url) { const r = await fetch(url); return r.json(); }
async function jpost(url, body) {
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  return r.json();
}

function drawSom(snap) {
  const c = document.getElementById('som');
  const ctx = c.getContext('2d');
  const gw = snap.grid_w || 10, gh = snap.grid_h || 10;
  const cell = c.width / gw;
  const density = snap.density || [];
  let max = 1;
  for (const row of density) for (const v of row) if (v > max) max = v;
  ctx.fillStyle = '#000'; ctx.fillRect(0, 0, c.width, c.height);
  for (let x = 0; x < gw; x++) {
    for (let y = 0; y < gh; y++) {
      const v = (density[x] && density[x][y]) || 0;
      const t = Math.min(1, v / max);
      const g = Math.round(30 + t * 180);
      ctx.fillStyle = `rgb(${Math.round(g*0.2)},${g},${Math.round(g*0.9)})`;
      ctx.fillRect(x * cell, y * cell, cell - 1, cell - 1);
    }
  }
  ctx.font = '9px monospace';
  for (const a of (snap.recent_alerts || [])) {
    const px = a.x * cell + cell / 2, py = a.y * cell + cell / 2;
    ctx.fillStyle = 'rgba(255,70,70,0.9)';
    ctx.beginPath(); ctx.arc(px, py, 4, 0, 7); ctx.fill();
  }
}

function renderStats(status) {
  const el = document.getElementById('stats');
  el.innerHTML = `
    <span class="stat">SOM samples: <b>${status.som.trained_samples}</b></span>
    <span class="stat">Chờ gắn nhãn: <b>${status.active_learning_pending}</b></span>
    <span class="stat">rtl_433: <b>${status.rtl_433_available ? 'có' : 'không'}</b></span>
    <span class="stat">Teacher endpoint: <b>${status.teacher_endpoint_configured ? 'đã cấu hình' : 'chưa'}</b></span>
    <span class="stat">Webhooks: <b>${(status.webhooks_configured||[]).join(', ') || 'chưa cấu hình'}</b></span>
  `;
}

function renderQueue(items) {
  const tbody = document.querySelector('#queue-table tbody');
  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty">Queue trống — không có capture nào chờ gắn nhãn.</td></tr>';
    return;
  }
  tbody.innerHTML = items.map(it => `
    <tr data-id="${it.id}">
      <td>${it.channel}</td>
      <td>${(it.freq_hz/1e6).toFixed(3)}</td>
      <td>${it.threat_type}</td>
      <td>${(it.confidence*100).toFixed(0)}%</td>
      <td><span class="badge b-${it.status}">${it.status}</span></td>
      <td>
        <input class="label-input" placeholder="nhãn..." value="${it.threat_type}">
        <button onclick="doLabel('${it.id}', this)">Gắn nhãn</button>
        <button onclick="doDiscard('${it.id}')">Bỏ</button>
      </td>
    </tr>`).join('');
}

async function doLabel(id, btn) {
  const input = btn.parentElement.querySelector('.label-input');
  await jpost('/api/agents/label', {id: id, label: input.value, labeled_by: 'ui-analyst'});
  refresh();
}
async function doDiscard(id) {
  await jpost('/api/agents/discard', {id: id});
  refresh();
}

async function refresh() {
  try {
    const [status, som, queue] = await Promise.all([
      jget('/api/agents/status'), jget('/api/agents/som'),
      jget('/api/agents/queue?status=pending&limit=100'),
    ]);
    renderStats(status);
    drawSom(som);
    renderQueue(queue.items || []);
  } catch (e) { console.error(e); }
}
refresh();
setInterval(refresh, 4000);
</script>
</body>
</html>"""


class AgentSuite:
    """Single object SDR-BLUE-TEAM.py constructs and calls into every
    sweep round + registers into Flask once. Mirrors rf_sentinel_ui's
    dependency-injection register() pattern."""

    def __init__(self, logger,
                base_dir: str = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rf_logs"),
                sample_rate: float = 2.0e6,
                get_rf_fn: Optional[Callable] = None,
                webhooks: Optional[dict] = None,
                teacher_endpoint: Optional[str] = None,
                response_script: Optional[str] = None,
                retrain_script: Optional[str] = None,
                db_insert_labeled_fn: Optional[Callable] = None,
                min_response_level_value: int = 3,
                som_dim: int = 8):
        self.logger = logger
        self.base_dir = base_dir
        self.sample_rate = sample_rate
        self.get_rf_fn = get_rf_fn

        self.som            = SimpleSOM(dim=som_dim)
        self.freq_agent      = CognitiveFrequencyAgent(logger)
        self.active_learning = ActiveLearningAgent(
            base_dir, logger, retrain_script, db_insert_labeled_fn)
        self.teacher         = TeacherStudentBridge(self.active_learning, teacher_endpoint, logger)
        self.response_agent  = AutomatedResponseAgent(
            base_dir, logger, webhooks, response_script, min_response_level_value)
        self.decoder         = ProtocolDecoderAgent(base_dir, logger)
        self.bearing         = BearingEstimator()

        self._last_decode = defaultdict(float)
        self._decode_cooldown_s = 10.0
        self._recent_alerts = deque(maxlen=150)   # for the /agents SOM view

    def _log(self, msg, level="info"):
        _emit(self.logger, "AGENTS", msg, level)

    # ------------------------------------------------------------ main hook
    def process(self, channel, result, iq, engine=None, persist_count: int = 0):
        """Call this once per sweep, right after apply_confidence_gate()."""
        anomaly = getattr(result, "anomaly", None)
        confidence = _safe_float(getattr(result, "confidence", 0.0))
        threat_level_value = getattr(getattr(result, "threat_level", None), "value", 0)
        power_dbm = _safe_float(getattr(anomaly, "power_dbm", -100.0))

        # ---- Cognitive Frequency Agent: gain + FHSS focus tracking -------
        try:
            sdr_proxy = getattr(engine, "sdr", None) if engine is not None else None
            self.freq_agent.maybe_adjust_gain(sdr_proxy, iq, channel.name, power_dbm)
            dtw = _safe_float(getattr(anomaly, "dtw_fhss_score", 0.0))
            if dtw:
                self.freq_agent.note_fhss(channel.name, dtw)
        except Exception as e:
            report_error("AgentSuite freq_agent", e)

        # ---- SOM: only "observe" (learn) clean samples; always compute ---
        # edge_score so alerted samples never get absorbed into "normal".
        try:
            vec = _feature_vector(anomaly)
            if threat_level_value == 0:
                self.som.observe(vec)
            edge = self.som.edge_score(vec)
            if threat_level_value > 0:
                bx, by = self.som.bmu(vec)
                self._recent_alerts.append({
                    "x": bx, "y": by,
                    "channel": channel.name,
                    "threat_type": getattr(result, "threat_type", ""),
                    "severity": getattr(getattr(result, "threat_level", None), "name", ""),
                    "edge": round(edge, 3),
                    "ts": _now_iso(),
                })
            if edge > 0.85 and threat_level_value == 0:
                result.indicators.append(
                    f"[SOM] Tin hieu roi ra ria ban do tu to chuc "
                    f"(edge={edge:.2f}) — la nhung con chua vuot nguong.")
        except Exception as e:
            report_error("AgentSuite SOM", e)

        # ---- Active Learning + Teacher-Student on low confidence ---------
        entry_id = None
        try:
            if self.active_learning.should_enqueue(confidence):
                p_ratio = persist_count / 5.0  # PERSISTENCE_WINDOW default; cosmetic only
                entry_id = self.active_learning.enqueue(result, iq, self.sample_rate, p_ratio)
                self.teacher.maybe_escalate(result, iq, self.sample_rate, entry_id)
        except Exception as e:
            report_error("AgentSuite active_learning", e)

        # ---- Protocol decode for IoT/LoRa-type channels (rate-limited) ---
        decoded = None
        try:
            if self.decoder.should_decode(channel.threat_type):
                now = time.time()
                if now - self._last_decode[channel.name] > self._decode_cooldown_s:
                    self._last_decode[channel.name] = now
                    decoded = self.decoder.decode(iq, self.sample_rate,
                                                  channel.freq_hz, channel.name)
                    if decoded and decoded.get("packets"):
                        result.indicators.append(
                            f"[DECODE] {len(decoded['packets'])} goi tin ISM giai ma duoc.")
        except Exception as e:
            report_error("AgentSuite decoder", e)

        # ---- Automated Response on HIGH/CRITICAL --------------------------
        response = None
        try:
            if threat_level_value >= self.response_agent.min_level_value:
                sigmf_paths = None
                if entry_id is None:
                    # not already queued by active-learning -> write sigmf now
                    base = os.path.join(self.response_agent.dir,
                                        f"{_stamp()}_{channel.name}")
                    d, m = write_sigmf(iq, self.sample_rate, channel.freq_hz, base)
                    sigmf_paths = {"data": d, "meta": m}
                response = self.response_agent.handle(
                    result, iq, self.sample_rate, sigmf_paths=sigmf_paths)
        except Exception as e:
            report_error("AgentSuite response_agent", e)

        return {"entry_id": entry_id, "decoded": decoded, "response": response}

    def retrain_tick(self):
        try:
            self.active_learning.maybe_retrain(self.get_rf_fn)
        except Exception as e:
            report_error("AgentSuite retrain_tick", e)

    # --------------------------------------------------------------- Flask
    def register_flask(self, app) -> None:
        if app is None:
            return
        try:
            from flask import jsonify, request
        except ImportError as e:
            report_error("register_flask", e, every=None, level="warning")
            return

        @app.route("/api/agents/status")
        def _agents_status():
            return jsonify({
                "som": self.som.snapshot(),
                "active_learning_pending": len(self.active_learning.list_queue("pending")),
                "rtl_433_available": self.decoder._rtl_433_path is not None,
                "teacher_endpoint_configured": bool(self.teacher.endpoint),
                "response_script_configured": bool(self.response_agent.response_script),
                "webhooks_configured": list(self.response_agent.webhooks.keys()),
            })

        @app.route("/api/agents/som")
        def _agents_som():
            snap = self.som.snapshot()
            snap["recent_alerts"] = list(self._recent_alerts)
            return jsonify(snap)

        @app.route("/agents")
        def _agents_dashboard():
            return _AGENTS_DASHBOARD_HTML

        @app.route("/api/agents/queue")
        def _agents_queue():
            status = request.args.get("status", "pending")
            limit = min(int(request.args.get("limit", 100)), 500)
            return jsonify({"items": self.active_learning.list_queue(status, limit)})

        @app.route("/api/agents/label", methods=["POST"])
        def _agents_label():
            body = request.get_json(force=True, silent=True) or {}
            entry_id = body.get("id")
            label = body.get("label")
            by = body.get("labeled_by", "analyst")
            if not entry_id or not label:
                return jsonify({"ok": False, "error": "can id va label"}), 400
            ok = self.active_learning.label(entry_id, label, by)
            self.active_learning.maybe_retrain(self.get_rf_fn)
            return jsonify({"ok": ok})

        @app.route("/api/agents/discard", methods=["POST"])
        def _agents_discard():
            body = request.get_json(force=True, silent=True) or {}
            entry_id = body.get("id")
            return jsonify({"ok": self.active_learning.discard(entry_id) if entry_id else False})

        @app.route("/api/agents/aoa/sample", methods=["POST"])
        def _agents_aoa_sample():
            body = request.get_json(force=True, silent=True) or {}
            try:
                self.bearing.add_sample(body["channel"], body["angle_deg"], body["rssi_dbm"])
                return jsonify({"ok": True})
            except KeyError as e:
                return jsonify({"ok": False, "error": f"thieu truong {e}"}), 400

        @app.route("/api/agents/aoa/estimate")
        def _agents_aoa_estimate():
            channel = request.args.get("channel", "")
            est = self.bearing.estimate(channel)
            return jsonify({"estimate": est})

        self._log("da dang ky /api/agents/* routes vao Flask.")
