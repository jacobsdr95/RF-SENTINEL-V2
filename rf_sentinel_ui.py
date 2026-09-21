#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rf_sentinel_ui.py — RF Sentinel Web UI  (tách riêng khỏi SDR-BLUE-TEAM.py)

Tích hợp vào SDR-BLUE-TEAM.py bằng cách:
    1. import rf_sentinel_ui as _ui
    2. _ui.register(WEB_APP, _get_rf, db_*)   # thay thế toàn bộ phần Flask cũ
    3. Xoá PAGE string và @WEB_APP.route cũ

Các tính năng mới so với UI cũ:
    ✅  Chart.js: Donut (threat types), Line (power timeline), Bar (hourly)
    ✅  Heatmap tần số (activity theo band)
    ✅  Server-Sent Events cho real-time updates (không cần reload)
    ✅  Export CSV / JSON tất cả events
    ✅  Calibration wizard — nhập offset từng band, set CALIBRATION_VERIFIED
    ✅  Panel RF model: accuracy, classes, degenerate status
    ✅  Channel watchlist panel (baseline, last zscore)
    ✅  Filter: severity, threat type, channel, time range
    ✅  /api/stream  — SSE endpoint
    ✅  /api/export  — CSV hoặc JSON download
    ✅  /api/calibration GET/POST — đọc/ghi offset
    ✅  /api/channels — trạng thái từng channel
"""

from __future__ import annotations

import csv
import importlib
import io
import json
import logging
import os
import queue
import sys
import threading
import time
import traceback
from datetime import datetime, timezone
from typing import Callable

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

# ---------------------------------------------------------------------------
# _dyn_import — load module/attr bằng importlib, trả None nếu thiếu.
# Dùng để hot-swap dependency mà không cần restart process.
# ---------------------------------------------------------------------------
def _dyn_import(module_name: str, attr: str | None = None):
    try:
        mod = importlib.import_module(module_name)
        return getattr(mod, attr) if attr else mod
    except (ImportError, AttributeError) as e:
        report_error(f"DEP {module_name}" + (f".{attr}" if attr else ""),
                     e, every=None, level="warning")
        return None

# ---------------------------------------------------------------------------
# SSE broadcast — non-blocking two-stage design
#
# Problem với cách cũ (single-stage):
#   broadcast_sse() → giữ _sse_lock → duyệt clients → put_nowait mỗi queue
#   Nếu có N tabs mở, hàm này block db_log_event() O(N) time.
#   Với N=10 clients và mỗi put_nowait ~1µs → 10µs overhead không đáng kể,
#   nhưng nếu queue.Full → remove client → O(N) list scan mỗi event.
#
# Giải pháp (two-stage):
#   Stage 1 (hot path):  broadcast_sse() → put_nowait vào _fan_out_queue
#                        O(1), non-blocking, không cần lock.
#   Stage 2 (background): _broadcaster thread đọc _fan_out_queue
#                         → phân phát tới từng client queue.
#                         Lock chỉ giữ khi register/unregister client.
#
# db_log_event() không bao giờ bị block bởi logic SSE.
# ---------------------------------------------------------------------------

_sse_clients: list[queue.Queue] = []
_sse_lock    = threading.Lock()

# Fan-out queue: broadcast_sse() chỉ put vào đây, không động tới client list
_fan_out_queue: queue.Queue = queue.Queue(maxsize=512)
_broadcaster_thread: threading.Thread | None = None


def _broadcaster_loop() -> None:
    """
    Background daemon thread — single consumer của _fan_out_queue.
    Phân phát message tới từng client và dọn client chết.
    Thread này là consumer duy nhất → không cần lock khi pop.
    Lock chỉ dùng khi modify _sse_clients list.
    """
    while True:
        msg = _fan_out_queue.get()      # blocking; the old 30 s timeout only ever looped back

        if msg is None:       # poison pill — shutdown signal (optional)
            break

        dead: list[queue.Queue] = []
        with _sse_lock:
            snapshot = list(_sse_clients)   # copy để release lock nhanh

        for q in snapshot:
            try:
                q.put_nowait(msg)
            except queue.Full as e:
                dead.append(q)
                report_error("SSE client too slow — disconnected", e, every=60, level="warning")

        if dead:
            with _sse_lock:
                for q in dead:
                    if q in _sse_clients:      # may already be gone (client closed first)
                        _sse_clients.remove(q)


def _ensure_broadcaster() -> None:
    """Khởi tạo broadcaster thread lần đầu (lazy, thread-safe)."""
    global _broadcaster_thread
    if _broadcaster_thread is not None and _broadcaster_thread.is_alive():
        return
    with _sse_lock:
        # Double-checked locking
        if _broadcaster_thread is None or not _broadcaster_thread.is_alive():
            _broadcaster_thread = threading.Thread(
                target=_broadcaster_loop,
                daemon=True,
                name="sse-broadcaster",
            )
            _broadcaster_thread.start()


def broadcast_sse(data: dict) -> None:
    """
    HOT PATH — gọi từ db_log_event() sau mỗi insert.

    Thiết kế:
    - Không giữ lock.
    - Không động đến _sse_clients.
    - Chỉ put_nowait vào _fan_out_queue → O(1), thường < 1µs.
    - Nếu queue đầy (512 events pending, broadcaster bị lag) → drop + báo lỗi
      (rate-limited). Prefer dropping stale events hơn blocking log pipeline.
    """
    _ensure_broadcaster()
    try:
        _fan_out_queue.put_nowait(
            f"data: {json.dumps(data, default=str)}\n\n"
        )
    except queue.Full as e:
        # Drop rather than block the log pipeline — but a drop is data the
        # browser never sees, so it is reported (rate-limited), not hidden.
        report_error("SSE fan-out queue full — event NOT pushed to browsers",
                     e, every=60, level="warning")


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------
_PAGE = r"""<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RF Sentinel — Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"
        onerror="var s=document.createElement('script');s.src='/vendor/chart.js';document.head.appendChild(s)"></script>
<noscript id="_chartjs_offline_note" style="display:block;color:#f5c842;padding:4px 8px;font-size:11px">
  ⚠ Bieu do khong hien thi: Chart.js CDN khong tai duoc va khong co tep ban dia
  (vendor/chart.umd.min.js). Chay: python get_vendor.py hoac xem CONTRIBUTING.md.
</noscript>
<script>
  // Remove offline warning as soon as Chart.js has actually loaded.
  (function(){function _rmNote(){var n=document.getElementById('_chartjs_offline_note');if(n)n.remove();}
  if(window.Chart){_rmNote();}else{document.currentScript.parentNode
    .lastElementChild.addEventListener('load',_rmNote);}})();
</script>
<style>
/* ─── reset + tokens ─────────────────────────────────────── */
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0b0f14; --panel:#101820; --border:#182430; --border2:#1e2f3d;
  --txt:#d6e1ea; --muted:#4a6070; --accent:#3eb8ff;
  --ok:#4ecb71; --low:#7eb8d4; --med:#f5c842; --high:#ff8c42; --crit:#ff4f4f;
  --font:'ui-monospace','Menlo','Cascadia Code',monospace;
  --radius:6px;
}
body{background:var(--bg);color:var(--txt);font:13px/1.55 var(--font);
     display:grid;grid-template-rows:48px 1fr;height:100vh;overflow:hidden}

/* ─── topbar ─────────────────────────────────────────────── */
#topbar{display:flex;align-items:center;gap:12px;padding:0 18px;
        border-bottom:1px solid var(--border);background:var(--panel)}
#topbar h1{font-size:13px;font-weight:600;letter-spacing:.06em;color:var(--accent);
           white-space:nowrap}
.badge{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;
       border-radius:12px;font-size:11px;background:var(--border2);color:var(--muted)}
.badge.ok{background:#0d2218;color:var(--ok)}
.badge.warn{background:#2a1f09;color:var(--med)}
.badge.bad{background:#2a0d0d;color:var(--crit)}
#conn{margin-left:auto;font-size:11px;color:var(--muted)}
#conn.live{color:var(--ok)}

/* ─── layout ─────────────────────────────────────────────── */
#main{display:grid;grid-template-columns:220px 1fr 280px;overflow:hidden}
#left,#right{overflow-y:auto;border-right:1px solid var(--border);padding:14px 12px}
#right{border-right:none;border-left:1px solid var(--border)}
#center{overflow-y:auto;padding:14px 16px;display:flex;flex-direction:column;gap:14px}

/* ─── panels ─────────────────────────────────────────────── */
.panel{background:var(--panel);border:1px solid var(--border);
       border-radius:var(--radius);padding:12px}
.panel h2{font-size:11px;letter-spacing:.07em;color:var(--muted);
          text-transform:uppercase;margin-bottom:10px;font-weight:500}

/* ─── channel list ───────────────────────────────────────── */
.ch-row{display:flex;justify-content:space-between;align-items:center;
        padding:5px 0;border-bottom:1px solid var(--border);font-size:12px}
.ch-row:last-child{border-bottom:none}
.ch-name{color:var(--txt);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:120px}
.ch-z{font-size:11px;padding:1px 6px;border-radius:8px;background:var(--border2);
      white-space:nowrap}
.ch-z.z-high{background:#2a1006;color:var(--crit)}
.ch-z.z-med{background:#2a1c06;color:var(--med)}
.ch-z.z-ok{color:var(--muted)}

/* ─── charts row ─────────────────────────────────────────── */
#chart-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
#chart-row .panel{padding:10px}
#chart-row canvas{width:100%!important;max-height:160px}

/* ─── heatmap ────────────────────────────────────────────── */
#heatmap-wrap{display:grid;gap:4px;padding-top:4px}
.hm-row{display:grid;grid-template-columns:90px 1fr;align-items:center;gap:8px;
        font-size:11px;color:var(--muted)}
.hm-bar{height:10px;border-radius:3px;background:var(--border2);overflow:hidden}
.hm-fill{height:100%;background:var(--accent);opacity:.85;border-radius:3px;
          transition:width .5s}

/* ─── events table ───────────────────────────────────────── */
#tbl-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:12px}
thead th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--border2);
         color:var(--muted);font-weight:500;text-transform:uppercase;
         font-size:10.5px;letter-spacing:.05em;white-space:nowrap;
         position:sticky;top:0;background:var(--panel);z-index:2}
tbody tr{transition:background .12s}
tbody tr:hover td{background:#111c26}
td{padding:5px 8px;border-bottom:1px solid var(--border);vertical-align:middle;
   white-space:nowrap}
.sev{padding:2px 7px;border-radius:9px;font-size:11px;font-weight:600}
.sev.CRITICAL{background:#2a0d0d;color:var(--crit)}
.sev.HIGH    {background:#2a1006;color:var(--high)}
.sev.MEDIUM  {background:#2a1c06;color:var(--med)}
.sev.LOW     {background:#0e1e28;color:var(--low)}
.sev.OK      {background:#0d2218;color:var(--ok)}
.conf-bar{width:60px;height:6px;background:var(--border2);border-radius:3px;overflow:hidden}
.conf-fill{height:100%;background:var(--accent)}
.mark-btn{background:none;border:none;cursor:pointer;padding:0 4px;
          font-size:14px;opacity:.7;transition:opacity .1s}
.mark-btn:hover{opacity:1}

/* ─── filters bar ────────────────────────────────────────── */
#filters{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
#filters select,#filters input{background:var(--border2);border:1px solid var(--border);
  color:var(--txt);padding:4px 8px;border-radius:var(--radius);font:inherit;
  font-size:12px;outline:none}
#filters select:focus,#filters input:focus{border-color:var(--accent)}
.export-btn{margin-left:auto;background:var(--border2);border:1px solid var(--border);
            color:var(--accent);padding:4px 12px;border-radius:var(--radius);
            cursor:pointer;font:inherit;font-size:12px;transition:background .15s}
.export-btn:hover{background:#182838}

/* ─── right panel details ────────────────────────────────── */
.kv{display:flex;justify-content:space-between;font-size:12px;
    padding:4px 0;border-bottom:1px solid var(--border)}
.kv:last-child{border-bottom:none}
.kv .k{color:var(--muted)}
.kv .v{color:var(--txt);text-align:right;max-width:140px;
       overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.kv .v.ok{color:var(--ok)} .kv .v.warn{color:var(--med)} .kv .v.bad{color:var(--crit)}

/* ─── calibration wizard ─────────────────────────────────── */
#cal-form{display:none;flex-direction:column;gap:6px;margin-top:8px}
#cal-form.open{display:flex}
.cal-row{display:grid;grid-template-columns:1fr 70px;gap:6px;font-size:11px;
         align-items:center;color:var(--muted)}
.cal-row input{background:var(--border2);border:1px solid var(--border);
               color:var(--txt);padding:2px 6px;border-radius:4px;font:inherit;
               text-align:right;width:100%}
.cal-save{margin-top:4px;background:#102030;border:1px solid var(--accent);
          color:var(--accent);padding:4px 12px;border-radius:var(--radius);
          cursor:pointer;font:inherit;font-size:12px}
.cal-toggle{background:none;border:1px solid var(--border);color:var(--muted);
            padding:3px 10px;border-radius:var(--radius);cursor:pointer;
            font:inherit;font-size:11px;margin-top:6px}
.cal-toggle:hover{border-color:var(--accent);color:var(--accent)}
</style>
</head>
<body>

<!-- ── topbar ──────────────────────────────────────────── -->
<div id="topbar">
  <h1>RF SENTINEL</h1>
  <span class="badge" id="b-rf">rf: ...</span>
  <span class="badge" id="b-lbl">labels: ...</span>
  <span class="badge" id="b-cal">cal: ...</span>
  <span id="conn">connecting…</span>
</div>

<!-- ── main grid ───────────────────────────────────────── -->
<div id="main">

  <!-- left: channel watchlist -->
  <div id="left">
    <div class="panel">
      <h2>Watchlist Channels</h2>
      <div id="ch-list"><span style="color:var(--muted);font-size:12px">Loading…</span></div>
    </div>
  </div>

  <!-- center: charts + table -->
  <div id="center">

    <!-- charts row -->
    <div id="chart-row">
      <div class="panel">
        <h2>Threat Breakdown</h2>
        <canvas id="c-donut"></canvas>
      </div>
      <div class="panel">
        <h2>Power Timeline (last 60 events)</h2>
        <canvas id="c-line"></canvas>
      </div>
      <div class="panel">
        <h2>Events / Hour (last 24h)</h2>
        <canvas id="c-bar"></canvas>
      </div>
    </div>

    <!-- freq heatmap -->
    <div class="panel">
      <h2>Activity by Frequency Band</h2>
      <div id="heatmap-wrap"></div>
    </div>

    <!-- filter bar -->
    <div class="panel" style="padding:8px 12px">
      <div id="filters">
        <select id="f-sev">
          <option value="">All severities</option>
          <option>CRITICAL</option><option>HIGH</option>
          <option>MEDIUM</option><option>LOW</option><option>OK</option>
        </select>
        <select id="f-type">
          <option value="">All threat types</option>
          <option>GPS_JAM</option><option>GPS_SPOOF</option>
          <option>FAKE_BTS</option><option>CELL_JAM</option>
          <option>DRONE_FHSS</option><option>IOT_REPLAY</option>
          <option>WIFI_DEAUTH</option><option>ADSB_SPOOF</option>
          <option>SATCOM</option><option>EMERGENCY</option>
        </select>
        <input id="f-ch" placeholder="channel filter…" style="width:140px">
        <button class="export-btn" onclick="doExport('csv')">⬇ CSV</button>
        <button class="export-btn" onclick="doExport('json')">⬇ JSON</button>
      </div>
    </div>

    <!-- events table -->
    <div class="panel" style="padding:0;overflow:hidden">
      <div id="tbl-wrap">
        <table>
          <thead><tr>
            <th>Time (UTC)</th><th>Channel</th><th>Freq</th>
            <th>Type</th><th>Severity</th>
            <th>Z</th><th>Confidence</th><th>AI-1</th><th>AI-2</th>
            <th>RF Label</th><th>Mark</th>
          </tr></thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
    </div>

  </div><!-- /center -->

  <!-- right: model + calibration -->
  <div id="right">

    <!-- RF model panel -->
    <div class="panel" style="margin-bottom:12px">
      <h2>Random Forest Model</h2>
      <div id="rf-kv">
        <div class="kv"><span class="k">Status</span><span class="v" id="rf-status">—</span></div>
        <div class="kv"><span class="k">Classes</span><span class="v" id="rf-classes">—</span></div>
        <div class="kv"><span class="k">CV-5 Acc</span><span class="v" id="rf-cv5">—</span></div>
        <div class="kv"><span class="k">Holdout Acc</span><span class="v" id="rf-hold">—</span></div>
        <div class="kv"><span class="k">Degenerate</span><span class="v" id="rf-degen">—</span></div>
        <div class="kv"><span class="k">Labeled / Need</span><span class="v" id="rf-lbl">—</span></div>
        <div class="kv"><span class="k">Max class share</span><span class="v" id="rf-share">—</span></div>
      </div>
      <div id="rf-hint" style="margin-top:8px;font-size:11px;color:var(--med)"></div>
    </div>

    <!-- calibration panel -->
    <div class="panel">
      <h2>Power Calibration</h2>
      <div class="kv" style="margin-bottom:4px">
        <span class="k">Verified</span>
        <span class="v" id="cal-verified">—</span>
      </div>
      <div style="font-size:11px;color:var(--muted);margin-bottom:4px">
        Nhập offset (dB) cho từng band sau khi đo bằng signal generator.
        Offset = power_thực_tế − power_đọc_được.
      </div>
      <button class="cal-toggle" onclick="toggleCal()">⚙ Calibration Wizard</button>
      <form id="cal-form">
        <div id="cal-rows"></div>
        <button type="button" class="cal-save" onclick="saveCal()">💾 Lưu &amp; Verify</button>
      </form>
    </div>

    <!-- summary stats -->
    <div class="panel" style="margin-top:12px">
      <h2>Summary (All Time)</h2>
      <div id="summary-kv"></div>
    </div>

  </div><!-- /right -->
</div><!-- /main -->

<script>
'use strict';

// ── state ─────────────────────────────────────────────────
let allEvents = [];
let donutChart, lineChart, barChart;
let sseSource = null;

// ── chart init ────────────────────────────────────────────
const COLORS = {
  CRITICAL:'#ff4f4f', HIGH:'#ff8c42', MEDIUM:'#f5c842',
  LOW:'#7eb8d4', OK:'#4ecb71', _default:'#3eb8ff'
};

function initCharts() {
  const co = document.getElementById('c-donut').getContext('2d');
  donutChart = new Chart(co, {
    type:'doughnut',
    data:{labels:[],datasets:[{data:[],backgroundColor:[],borderWidth:0}]},
    options:{plugins:{legend:{labels:{color:'#4a6070',font:{size:11}}}},
             cutout:'65%',responsive:true,maintainAspectRatio:true}
  });

  const cl = document.getElementById('c-line').getContext('2d');
  lineChart = new Chart(cl, {
    type:'line',
    data:{labels:[],datasets:[{label:'Power (dBm)',data:[],
         borderColor:'#3eb8ff',backgroundColor:'rgba(62,184,255,.08)',
         borderWidth:1.5,pointRadius:2,tension:.4,fill:true}]},
    options:{plugins:{legend:{display:false}},
             scales:{x:{ticks:{color:'#4a6070',font:{size:10},maxTicksLimit:8}},
                     y:{ticks:{color:'#4a6070',font:{size:10}}}},
             responsive:true,maintainAspectRatio:true}
  });

  const cb = document.getElementById('c-bar').getContext('2d');
  barChart = new Chart(cb, {
    type:'bar',
    data:{labels:[],datasets:[{label:'Events',data:[],
         backgroundColor:'rgba(62,184,255,.5)',borderColor:'#3eb8ff',borderWidth:1}]},
    options:{plugins:{legend:{display:false}},
             scales:{x:{ticks:{color:'#4a6070',font:{size:10}}},
                     y:{ticks:{color:'#4a6070',font:{size:10},stepSize:1}}},
             responsive:true,maintainAspectRatio:true}
  });
}

// ── update charts ─────────────────────────────────────────
function updateCharts(events) {
  // donut — threat type counts
  const typeCnt = {};
  events.forEach(e => { typeCnt[e.threat_type] = (typeCnt[e.threat_type]||0)+1; });
  donutChart.data.labels = Object.keys(typeCnt);
  donutChart.data.datasets[0].data = Object.values(typeCnt);
  donutChart.data.datasets[0].backgroundColor =
    Object.keys(typeCnt).map((_,i) => `hsl(${(i*47)%360},60%,55%)`);
  donutChart.update('none');

  // line — power last 60
  const pw = events.slice(0,60).reverse();
  lineChart.data.labels = pw.map(e => (e.ts||'').slice(11,19));
  lineChart.data.datasets[0].data = pw.map(e => +(e.power_dbm||0).toFixed(1));
  lineChart.update('none');

  // bar — events per hour last 24h
  const now = Date.now();
  const hBuckets = Array(24).fill(0);
  events.forEach(e => {
    if (!e.ts) return;
    const ago = (now - new Date(e.ts+'Z').getTime()) / 3.6e6;
    if (ago < 24) hBuckets[Math.floor(ago)]++;
  });
  const labels = hBuckets.map((_,i) => i===0?'now':`-${i}h`);
  barChart.data.labels = labels.slice().reverse();
  barChart.data.datasets[0].data = hBuckets.slice().reverse();
  barChart.update('none');
}

// ── heatmap ───────────────────────────────────────────────
const BANDS = [
  {label:'VHF 100-300M', lo:100e6, hi:300e6},
  {label:'UHF 300-700M', lo:300e6, hi:700e6},
  {label:'800M-1GHz',    lo:800e6, hi:1000e6},
  {label:'GPS L-Band',   lo:1200e6,hi:1600e6},
  {label:'1.6G-2.4G',   lo:1600e6,hi:2400e6},
  {label:'2.4G (WiFi)',  lo:2400e6,hi:2500e6},
  {label:'3G-6GHz',     lo:3000e6,hi:6000e6},
];

function updateHeatmap(events) {
  const counts = BANDS.map(b => ({...b, n:0}));
  events.forEach(e => {
    const f = +(e.freq_hz||0);
    counts.forEach(b => { if (f>=b.lo && f<b.hi) b.n++; });
  });
  const maxN = Math.max(1, ...counts.map(b=>b.n));
  const wrap = document.getElementById('heatmap-wrap');
  wrap.innerHTML = counts.map(b => `
    <div class="hm-row">
      <span>${b.label}</span>
      <div class="hm-bar">
        <div class="hm-fill" style="width:${Math.round(b.n/maxN*100)}%"></div>
      </div>
      <span style="font-size:10px;color:var(--muted);white-space:nowrap">${b.n}</span>
    </div>`).join('');
}

// ── table ─────────────────────────────────────────────────
function sevBadge(s){
  return `<span class="sev ${s||''}">${s||''}</span>`;
}
function confBar(c){
  return `<div class="conf-bar"><div class="conf-fill" style="width:${
    Math.round(Math.max(0,Math.min(1,c||0))*100)}%"></div></div>`;
}

function renderTable() {
  const sev  = document.getElementById('f-sev').value;
  const type = document.getElementById('f-type').value;
  const ch   = document.getElementById('f-ch').value.toLowerCase();

  const rows = allEvents.filter(e =>
    (!sev  || e.severity === sev) &&
    (!type || e.threat_type === type) &&
    (!ch   || (e.channel||'').toLowerCase().includes(ch))
  );

  document.getElementById('rows').innerHTML = rows.map(e => `<tr>
    <td>${(e.ts||'').slice(0,19).replace('T',' ')}</td>
    <td>${e.channel||''}</td>
    <td>${((e.freq_hz||0)/1e6).toFixed(3)}M</td>
    <td style="color:var(--muted)">${e.threat_type||''}</td>
    <td>${sevBadge(e.severity)}</td>
    <td style="color:${Math.abs(e.zscore||0)>3?'var(--crit)':'var(--txt)'}">
      ${(+(e.zscore||0)).toFixed(2)}</td>
    <td>${confBar(e.confidence)}</td>
    <td style="font-size:11px;color:var(--muted)">${e.hybrid_ai_label||''}</td>
    <td style="font-size:11px;color:var(--muted)">${e.type_ai_label||''}</td>
    <td style="font-size:11px">${e.rf_label
        ? `<span style="color:var(--accent)">${e.rf_label}</span> ${(e.rf_confidence||0).toFixed(2)}`
        : '<span style="color:var(--muted)">—</span>'}</td>
    <td>${e.confirmed===1
        ? '<span style="color:var(--ok)">✓</span>'
        : e.confirmed===0
        ? '<span style="color:var(--crit)">✗</span>'
        : `<button class="mark-btn" onclick="mark(${e.id},1)" title="Confirm">✓</button>
           <button class="mark-btn" style="color:var(--crit)" onclick="mark(${e.id},0)" title="Reject">✗</button>`
    }</td>
  </tr>`).join('');
}

// ── mark event ────────────────────────────────────────────
async function mark(id, v) {
  await fetch('/api/label', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id, confirmed:v})
  });
  await refresh();
}

// ── error reporting: never swallow a failure in the browser either ──────────
// Logs to the console AND records it on the connection badge (hover to read it),
// so a panel that stays empty always leaves a trace.
function reportUiError(where, err) {
  console.error('[RF-Sentinel UI] ' + where + ':', err);
  const c = document.getElementById('conn');
  if (c) c.title = 'Last UI error in ' + where + ': ' + err;
}

// ── channel watchlist ─────────────────────────────────────
async function refreshChannels() {
  try {
    const d = await (await fetch('/api/channels')).json();
    document.getElementById('ch-list').innerHTML = d.channels.map(ch => {
      const z = +(ch.zscore_last||0);
      const zClass = Math.abs(z)>3?'z-high':Math.abs(z)>1.5?'z-med':'z-ok';
      return `<div class="ch-row">
        <span class="ch-name" title="${ch.name} — ${(+ch.freq_hz/1e6).toFixed(2)}MHz">${ch.name}</span>
        <span class="ch-z ${zClass}">z=${z.toFixed(1)}</span>
      </div>`;
    }).join('');
  } catch(err) { reportUiError('refreshChannels', err); }
}

// ── RF model panel ────────────────────────────────────────
function updateRFPanel(d) {
  const rf = d.rf || {};
  const lbl = d.labeling || {};

  const el = (id, text, cls='') => {
    const e = document.getElementById(id);
    if (e) { e.textContent = text; e.className = `v${cls?' '+cls:''}`; }
  };

  el('rf-status',
     rf.usable ? 'TRAINED' : rf.degenerate ? 'DEGENERATE' : 'UNTRAINED',
     rf.usable ? 'ok' : rf.degenerate ? 'bad' : 'warn');
  el('rf-classes', rf.classes ? rf.classes.join(', ') : '—');
  el('rf-cv5',     rf.cv5_acc  != null ? (rf.cv5_acc*100).toFixed(1)+'%'  : '—');
  el('rf-hold',    rf.holdout_acc != null ? (rf.holdout_acc*100).toFixed(1)+'%' : '—');
  el('rf-degen',   rf.degenerate ? 'YES' : 'NO', rf.degenerate ? 'bad':'ok');
  el('rf-lbl',     `${lbl.labeled||0} / ${lbl.needed||200}`,
     (lbl.labeled||0) >= (lbl.needed||200) ? 'ok' : 'warn');
  el('rf-share',   lbl.top_share != null ? (lbl.top_share*100).toFixed(0)+'%' : '—',
     (lbl.top_share||0) > 0.85 ? 'bad' : 'ok');

  const hint = document.getElementById('rf-hint');
  if (!rf.usable) {
    if ((lbl.classes||0) < 2)
      hint.textContent = 'Cần ≥2 loại threat được label. Nhấn ✓/✗ trên bảng.';
    else if ((lbl.top_share||0) > 0.85)
      hint.textContent = 'Mất cân bằng: 1 class >85%. Label thêm các loại khác.';
    else
      hint.textContent = 'Đang thu thập labels. Model sẽ tự train khi đủ dữ liệu.';
  } else hint.textContent = '';

  // topbar badges
  const bRf = document.getElementById('b-rf');
  bRf.textContent = rf.usable ? `rf: ${(rf.classes||[]).length} classes` :
                    rf.degenerate ? 'rf: degenerate' : 'rf: untrained';
  bRf.className = 'badge ' + (rf.usable ? 'ok' : 'warn');

  const bLbl = document.getElementById('b-lbl');
  bLbl.textContent = `labels: ${lbl.labeled||0}/${lbl.needed||200}`;
  bLbl.className = 'badge ' + ((lbl.labeled||0)>=(lbl.needed||200) ? 'ok':'warn');
}

// ── summary ───────────────────────────────────────────────
async function refreshSummary() {
  try {
    const d = await (await fetch('/api/summary')).json();
    const breakdown = d.breakdown || [];
    document.getElementById('summary-kv').innerHTML = breakdown.slice(0,8).map(r =>
      `<div class="kv">
        <span class="k">${r.threat_type||'?'} ${r.severity||''}</span>
        <span class="v">${r.n}</span>
      </div>`
    ).join('') || '<div style="color:var(--muted);font-size:12px">No data yet.</div>';
  } catch(err) { reportUiError('refreshSummary', err); }
}

// ── calibration ───────────────────────────────────────────
async function loadCalibration() {
  try {
    const d = await (await fetch('/api/calibration')).json();
    const el = document.getElementById('cal-verified');
    el.textContent = d.verified ? 'YES ✓' : 'NO (relative only)';
    el.className = 'v ' + (d.verified ? 'ok' : 'warn');
    document.getElementById('b-cal').textContent = d.verified ? 'cal: verified' : 'cal: uncalibrated';
    document.getElementById('b-cal').className = 'badge ' + (d.verified ? 'ok':'warn');

    // Populate wizard rows
    const rows = document.getElementById('cal-rows');
    rows.innerHTML = (d.bands||[]).map((b,i) => `
      <div class="cal-row">
        <span>${(b[0]/1e6).toFixed0()}–${(b[1]/1e6).toFixed0()} MHz</span>
        <input type="number" step="0.1" value="${b[2]}" id="cal-off-${i}"
               title="offset dB (positive = SDR reads too low)">
      </div>`).join('');
  } catch(err) { reportUiError('loadCalibration', err); }
}

Number.prototype.toFixed0 = function(){ return Math.round(this).toLocaleString(); };

function toggleCal() {
  const f = document.getElementById('cal-form');
  f.classList.toggle('open');
}

async function saveCal() {
  try {
    const d = await (await fetch('/api/calibration')).json();
    const bands = (d.bands||[]).map((b,i) => {
      const inp = document.getElementById(`cal-off-${i}`);
      return [b[0], b[1], inp ? +inp.value : b[2]];
    });
    const resp = await fetch('/api/calibration', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({bands, verified:true})
    });
    const out = await resp.json();
    alert(out.ok ? '✅ Calibration saved & verified!' : '❌ Error: '+out.error);
    await loadCalibration();
  } catch(e) { alert('Error: '+e); }
}

// ── export ────────────────────────────────────────────────
function doExport(fmt) {
  const sev  = document.getElementById('f-sev').value;
  const type = document.getElementById('f-type').value;
  const ch   = document.getElementById('f-ch').value;
  const params = new URLSearchParams();
  params.set('format', fmt);
  if (sev)  params.set('severity', sev);
  if (type) params.set('threat_type', type);
  if (ch)   params.set('channel', ch);
  window.location = '/api/export?' + params;
}

// ── main refresh ──────────────────────────────────────────
async function refresh() {
  try {
    const d = await (await fetch('/api/events?limit=200')).json();
    allEvents = d.events || [];
    updateCharts(allEvents);
    updateHeatmap(allEvents);
    renderTable();
    updateRFPanel(d);
    document.getElementById('conn').textContent = 'live · ' + new Date().toLocaleTimeString();
    document.getElementById('conn').className = 'live';
  } catch(e) {
    reportUiError('refresh', e);
    document.getElementById('conn').textContent = 'disconnected';
    document.getElementById('conn').className = '';
  }
}

// ── SSE connection ────────────────────────────────────────
function connectSSE() {
  if (sseSource) sseSource.close();
  sseSource = new EventSource('/api/stream');
  sseSource.onmessage = e => {
    try {
      const ev = JSON.parse(e.data);
      // Prepend new event and re-render (avoid full refresh)
      allEvents = [ev, ...allEvents].slice(0, 200);
      updateCharts(allEvents);
      updateHeatmap(allEvents);
      renderTable();
      document.getElementById('conn').textContent = 'live · ' + new Date().toLocaleTimeString();
      document.getElementById('conn').className = 'live';
    } catch(err) { reportUiError('SSE message', err); }
  };
  sseSource.onerror = () => {
    console.warn('[RF-Sentinel UI] SSE connection dropped — reconnecting in 3 s');
    document.getElementById('conn').textContent = 'reconnecting…';
    document.getElementById('conn').className = '';
    setTimeout(connectSSE, 3000);
  };
}

// ── filter listeners ──────────────────────────────────────
['f-sev','f-type','f-ch'].forEach(id =>
  document.getElementById(id).addEventListener('input', renderTable));

// ── boot ──────────────────────────────────────────────────
initCharts();
refresh();
refreshChannels();
refreshSummary();
loadCalibration();
connectSSE();
setInterval(refreshChannels, 10000);
setInterval(refreshSummary, 30000);
setInterval(loadCalibration, 60000);
// Fallback polling nếu SSE fail
setInterval(() => {
  if (!sseSource || sseSource.readyState === 2) refresh();
}, 5000);
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# API helpers — phụ thuộc vào SDR-BLUE-TEAM qua dependency injection
# ---------------------------------------------------------------------------

def register(
    app,
    get_rf_fn: Callable,
    db_fetch_recent_fn: Callable,
    db_fetch_labeled_fn: Callable,
    db_set_confirmed_fn: Callable,
    db_label_stats_fn: Callable,
    db_summary_stats_fn: Callable,
    db_channel_spectrum_fn: Callable,
    watchlist: list,
    cal_bands_ref: list,        # list of [lo, hi, offset] — mutable reference
    cal_verified_ref: list,     # [bool]  — mutable reference (single-element list)
    flask_port: int = 1717,
) -> None:
    """
    Đăng ký tất cả routes vào Flask app đã có.
    Dùng dependency injection thay vì import trực tiếp để tránh circular imports
    và để test dễ hơn.

    Ví dụ trong SDR-BLUE-TEAM.py:
        import rf_sentinel_ui as _ui
        _ui.register(
            WEB_APP, _get_rf,
            db_fetch_recent_events, db_fetch_labeled_events,
            db_set_confirmed, db_label_stats, db_summary_stats,
            db_channel_spectrum_history,
            WATCHLIST,
            cal_bands_ref=_CAL_BANDS_MUT,
            cal_verified_ref=_CAL_VERIFIED_MUT,
            flask_port=FLASK_PORT,
        )
    """
    try:
        from flask import jsonify, request, Response, stream_with_context
    except ImportError as e:
        report_error("rf_sentinel_ui.register", e, every=None, level="warning")
        return   # Flask not installed — routes are NOT registered

    # --------------------------------------------------------- vendored Chart.js
    # Served locally so the dashboard works fully offline.  The CDN <script>
    # in the HTML page has an onerror fallback that loads this route instead.
    _CHARTJS_PATH = os.path.join(os.path.dirname(__file__), "vendor", "chart.umd.min.js")

    @app.route("/vendor/chart.js")
    def vendor_chartjs():
        if not os.path.isfile(_CHARTJS_PATH):
            from flask import abort
            abort(404)
        with open(_CHARTJS_PATH, "rb") as fh:
            body = fh.read()
        return body, 200, {"Content-Type": "application/javascript; charset=utf-8",
                           "Cache-Control": "public, max-age=86400"}

    # ------------------------------------------------------------------ index
    @app.route("/")
    def index():
        return _PAGE.replace("{{port}}", str(flask_port))

    # ----------------------------------------------------------------- events
    @app.route("/api/events")
    def api_events():
        limit = min(int(request.args.get("limit", 100)), 1000)
        rows  = db_fetch_recent_fn(limit)
        rf    = get_rf_fn()
        lbl   = db_label_stats_fn()
        return jsonify({
            "count": len(rows),
            "events": rows,
            "rf": {
                "usable":      bool(rf and rf.usable),
                "degenerate":  bool(rf and rf.degenerate),
                "classes":     rf.classes_ if rf else [],
                "cv5_acc":     rf.cv5_acc  if rf else None,
                "holdout_acc": rf.holdout_acc if rf else None,
            },
            "labeling": lbl,
        })

    # ------------------------------------------------------------------ label
    @app.route("/api/label", methods=["POST"])
    def api_label():
        body      = request.get_json(force=True, silent=True) or {}
        ev_id     = body.get("id")
        confirmed = body.get("confirmed")
        if ev_id is None or confirmed not in (0, 1):
            return jsonify({"error": "need id and confirmed in {0,1}"}), 400
        ok = db_set_confirmed_fn(ev_id, int(confirmed))
        return jsonify({"ok": ok, "labeling": db_label_stats_fn()})

    # ----------------------------------------------------------------- summary
    @app.route("/api/summary")
    def api_summary():
        return jsonify(db_summary_stats_fn())

    # ---------------------------------------------------------------- channels
    @app.route("/api/channels")
    def api_channels():
        out = []
        for ch in watchlist:
            history = db_channel_spectrum_fn(ch.name, limit=1)
            last_z  = ch.zscore(history[0]["power_dbm"]) if history else 0.0
            out.append({
                "name":      ch.name,
                "freq_hz":   ch.freq_hz,
                "priority":  ch.priority,
                "threat_type": ch.threat_type,
                "baseline":  round(ch.baseline, 1),
                "std":       round(ch.std, 2),
                "zscore_last": round(last_z, 2),
                "samples":   len(ch._history),
            })
        return jsonify({"channels": out})

    # ------------------------------------------------------------- calibration
    @app.route("/api/calibration", methods=["GET", "POST"])
    def api_calibration():
        if request.method == "GET":
            return jsonify({
                "verified": bool(cal_verified_ref[0]),
                "bands": cal_bands_ref,
            })
        # POST — update offsets
        body = request.get_json(force=True, silent=True) or {}
        new_bands = body.get("bands")
        verified  = body.get("verified", False)
        if not new_bands or not isinstance(new_bands, list):
            return jsonify({"error": "need bands: [[lo,hi,offset],...]"}), 400
        try:
            # Validate and update in-place
            for i, b in enumerate(new_bands):
                if len(b) != 3:
                    raise ValueError(f"Band {i} malformed: {b}")
                cal_bands_ref[i] = [float(b[0]), float(b[1]), float(b[2])]
            cal_verified_ref[0] = bool(verified)
            return jsonify({"ok": True, "verified": cal_verified_ref[0],
                            "bands": cal_bands_ref})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

    # --------------------------------------------------------------- export
    @app.route("/api/export")
    def api_export():
        fmt       = request.args.get("format", "csv").lower()
        severity  = request.args.get("severity", "")
        ttype     = request.args.get("threat_type", "")
        channel   = request.args.get("channel", "")

        rows = db_fetch_recent_fn(limit=5000)
        if severity:
            rows = [r for r in rows if r.get("severity") == severity]
        if ttype:
            rows = [r for r in rows if r.get("threat_type") == ttype]
        if channel:
            rows = [r for r in rows
                    if channel.lower() in (r.get("channel") or "").lower()]

        if fmt == "json":
            out = json.dumps(rows, indent=2, default=str)
            return Response(
                out, mimetype="application/json",
                headers={"Content-Disposition":
                         "attachment; filename=rf_sentinel_export.json"})

        # CSV default
        if not rows:
            return Response("No data", mimetype="text/plain")
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
        return Response(
            buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition":
                     "attachment; filename=rf_sentinel_export.csv"})

    # --------------------------------------------------------------- SSE stream
    @app.route("/api/stream")
    def api_stream():
        # Đảm bảo broadcaster đang chạy trước khi client đầu tiên connect
        _ensure_broadcaster()

        q: queue.Queue = queue.Queue(maxsize=128)
        with _sse_lock:
            _sse_clients.append(q)

        def generate():
            # Ping ngay — browser xác nhận kết nối thành công
            yield "data: {\"type\":\"ping\"}\n\n"
            try:
                while True:
                    try:
                        # timeout=25s → keepalive trước khi browser tự đóng
                        msg = q.get(timeout=25)
                        yield msg
                    except queue.Empty:  # expected-exception: idle keepalive tick, not an error
                        yield "data: {\"type\":\"keepalive\"}\n\n"
            finally:
                # Client closed the tab (GeneratorExit propagates) or the stream
                # ended: unregister so the broadcaster stops feeding this queue.
                with _sse_lock:
                    if q in _sse_clients:      # _broadcaster_loop may have dropped it already
                        _sse_clients.remove(q)

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control":    "no-cache",
                "X-Accel-Buffering": "no",   # tắt Nginx buffering nếu có
            })

    # ------------------------------------------------------------- health
    @app.route("/api/health")
    def api_health():
        rf = get_rf_fn()
        return jsonify({
            "ok": True,
            "port": flask_port,
            "pid": os.getpid(),
            "rf_usable": bool(rf and rf.usable),
            "calibration_verified": bool(cal_verified_ref[0]),
            "sse_clients": len(_sse_clients),
        })
