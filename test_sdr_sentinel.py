"""
test_sdr_sentinel.py — Test suite cho RF Sentinel (SDR-BLUE-TEAM.py)

Chạy:
    python test_sdr_sentinel.py           # chạy tất cả, verbose
    python test_sdr_sentinel.py -v        # verbose mode
    python test_sdr_sentinel.py TestDSP   # chỉ chạy nhóm DSP

Không cần HackRF hay bất kỳ hardware nào.
Không cần pytest — dùng unittest built-in.

Cách tổ chức:
    TestDSP              — Hàm signal processing (FFT, entropy, kurtosis...)
    TestChannel          — Channel baseline tracking và z-score
    TestThreatRules      — Per-threat-type detection rules trong analyze()
    TestConfidenceGates  — PersistenceTracker và apply_confidence_gate()
    TestRXGuard          — ReceiveOnlySDRProxy chặn TX calls
    TestRFClassifier     — RFThreatClassifier gating + training guards
    TestDatabase         — SQLite CRUD với in-memory DB
    TestSignalFixtures   — Kiểm tra signal generators dùng trong các test khác
"""

from __future__ import annotations

import os
import sys
import math
import time
import unittest
import sqlite3
import tempfile
import threading

import importlib
import importlib.util as _ilu

# ---------------------------------------------------------------------------
# _dyn_import — load module/attr bằng importlib, trả None nếu thiếu
# ---------------------------------------------------------------------------
def _dyn_import(module_name: str, attr: str | None = None):
    try:
        mod = importlib.import_module(module_name)
        return getattr(mod, attr) if attr else mod
    except (ImportError, AttributeError) as e:
        print(f"[TEST] khong nap duoc {module_name}"
              f"{'.' + attr if attr else ''}: {type(e).__name__}: {e}", file=sys.stderr)
        return None

np = _dyn_import("numpy")
if np is None:
    raise ImportError("numpy is required — pip install numpy")

# ---------------------------------------------------------------------------
# Tìm SDR-BLUE-TEAM.py bằng NAME-MATCH trong cùng thư mục tuyệt đối
# (os.path.dirname(os.path.abspath(__file__))) — KHÔNG còn giả định tên
# thư mục repo cố định ("Receive-only-SDR-anomaly-detection-tool"), vì tên
# đó gãy ngay khi ai đó fork/đổi tên/đóng gói lại repo. Thứ tự tìm kiếm:
#   1. Cùng thư mục với chính test_sdr_sentinel.py này (trường hợp bình
#      thường: cả hai nằm trong real_warfare/).
#   2. Thư mục con "real_warfare/" cạnh test_sdr_sentinel.py (trường hợp
#      test được chạy từ thư mục gốc repo).
#   3. Bất kỳ thư mục con nào chứa "SDR-BLUE-TEAM*.py" (glob đệ quy 1 cấp)
#      — vẫn tuyệt đối, không phụ thuộc CWD.
# ---------------------------------------------------------------------------
import glob as _glob

_THIS_TEST_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_sdr_blue_team_py() -> str:
    candidates = (
        _glob.glob(os.path.join(_THIS_TEST_DIR, "SDR-BLUE-TEAM*.py")) +
        _glob.glob(os.path.join(_THIS_TEST_DIR, "real_warfare", "SDR-BLUE-TEAM*.py")) +
        _glob.glob(os.path.join(_THIS_TEST_DIR, "..", "real_warfare", "SDR-BLUE-TEAM*.py")) +
        _glob.glob(os.path.join(_THIS_TEST_DIR, "*", "SDR-BLUE-TEAM*.py"))
    )
    for c in candidates:
        if os.path.isfile(c):
            return os.path.abspath(c)
    raise FileNotFoundError(
        "Khong tim thay SDR-BLUE-TEAM*.py gan test_sdr_sentinel.py "
        f"(da tim trong {_THIS_TEST_DIR} va cac thu muc con/cha lien quan). "
        "Dat test_sdr_sentinel.py cung thu muc voi SDR-BLUE-TEAM.py, hoac "
        "trong thu muc cha cua real_warfare/.")


_SDR_PATH = _find_sdr_blue_team_py()
_SRC = os.path.dirname(_SDR_PATH)
sys.path.insert(0, _SRC)

import atexit
import contextlib
import inspect
import io
import logging
import queue
import shutil
import subprocess
import unittest.mock as mock

# Mọi file mà SDR-BLUE-TEAM.py ghi (sentinel.log, DB, evidence, reports, fingerprints)
# đều nằm dưới RF_LOGS_DIR, và RF_LOGS_DIR đọc biến môi trường này → trỏ nó vào một thư
# mục tạm: test không đụng vào ./rf_logs thật, mà log-file handler vẫn mở được (trước
# đây phải monkeypatch os.makedirs toàn cục và handler lặng lẽ hỏng).
_TEST_LOGS_DIR = tempfile.mkdtemp(prefix="rf_sentinel_test_")
os.environ["RF_SENTINEL_LOGS_DIR"] = _TEST_LOGS_DIR


def _cleanup_test_logs_dir():
    lg = logging.getLogger("rf_sentinel")
    for h in list(lg.handlers):          # release sentinel.log first (Windows keeps it locked)
        h.close()
        lg.removeHandler(h)
    try:
        shutil.rmtree(_TEST_LOGS_DIR)
    except Exception as e:
        print(f"[TEST] khong don duoc {_TEST_LOGS_DIR}: {e!r}", file=sys.stderr)


atexit.register(_cleanup_test_logs_dir)

# ---- dùng importlib.util để load file tên có gạch ngang ----
# Python không cho phép import "SDR-BLUE-TEAM" trực tiếp.
_spec = _ilu.spec_from_file_location("sdr_sentinel", _SDR_PATH)
sdr = _ilu.module_from_spec(_spec)
# BẮT BUỘC đăng ký vào sys.modules TRƯỚC khi exec (công thức chuẩn của importlib):
# @dataclass + annotations dạng chuỗi tra module qua sys.modules[cls.__module__];
# thiếu dòng này nó nhận None và nổ AttributeError ngay lúc import.
sys.modules["sdr_sentinel"] = sdr
try:
    _spec.loader.exec_module(sdr)
except BaseException:
    sys.modules.pop("sdr_sentinel", None)
    raise


# ===========================================================================
# Helpers tạo IQ signal giả cho test
# ===========================================================================

def make_noise_iq(n=4096, amplitude=50.0, seed=42) -> np.ndarray:
    """White Gaussian noise — entropy cao, kurtosis thấp (~3)."""
    rng = np.random.default_rng(seed)
    I = rng.standard_normal(n) * amplitude
    Q = rng.standard_normal(n) * amplitude
    return (I + 1j * Q).astype(np.complex64)


def make_tone_iq(n=4096, freq_hz=100e3, fs=2e6, amplitude=80.0) -> np.ndarray:
    """Sóng sin đơn tần — entropy thấp, detect_single_carrier=True."""
    t = np.arange(n) / fs
    iq = (amplitude * np.exp(2j * np.pi * freq_hz * t)).astype(np.complex64)
    return iq


def make_burst_iq(n=4096, burst_len=64, burst_amplitude=100.0, seed=7) -> np.ndarray:
    """Burst ngắn nằm trong nền nhiễu nhỏ — kurtosis rất cao."""
    rng = np.random.default_rng(seed)
    iq = (rng.standard_normal(n) + 1j * rng.standard_normal(n)).astype(np.complex64)
    # Chèn burst ở giữa
    mid = n // 2
    iq[mid:mid + burst_len] += burst_amplitude
    return iq


def make_repeating_iq(n=8192, period=200, amplitude=60.0) -> np.ndarray:
    """Tín hiệu lặp theo chu kỳ — cyclostationary_score cao."""
    iq = np.zeros(n, dtype=np.complex64)
    for start in range(0, n, period):
        end = min(start + period // 4, n)
        iq[start:end] = amplitude
    return iq


def make_empty_iq() -> np.ndarray:
    return np.zeros(0, dtype=np.complex64)


def make_dummy_anomaly_result(**overrides) -> sdr.EW_AnomalyResult:
    """Tạo EW_AnomalyResult mặc định (tất cả flags=False, scores=0)."""
    defaults = dict(
        channel="GPS_L1",
        freq_hz=1575.42e6,
        threat_type="GPS_JAM",
        power_dbm=-60.0,
        baseline_dbm=-70.0,
        zscore=0.0,
        entropy=0.8,
        kurtosis=3.0,
        sample_entropy=0.5,
        stft_entropy=5.0,
        cyclo_score=0.1,
        single_carrier=False,
        gsm_fcch=0.0,
        snr_db=10.0,
        bandwidth_hz=2e6,
        duration_ms=5.0,
        hybrid_ai_score=0.0,
        hybrid_ai_label="UNTRAINED",
        type_ai_score=0.0,
        type_ai_label="UNTRAINED",
        power_alert=False,
        entropy_alert=False,
        hybrid_ai_alert=False,
        type_ai_alert=False,
        burst_alert=False,
        structural_alert=False,
        swept_alert=False,
    )
    defaults.update(overrides)
    return sdr.EW_AnomalyResult(**defaults)


# ===========================================================================
# TestSignalFixtures — kiểm tra helpers bên trên trước khi dùng trong tests khác
# ===========================================================================

class TestSignalFixtures(unittest.TestCase):

    def test_noise_shape_and_dtype(self):
        iq = make_noise_iq(n=1024)
        self.assertEqual(iq.shape, (1024,))
        self.assertEqual(iq.dtype, np.complex64)

    def test_tone_is_narrowband(self):
        """Sóng sin đơn tần phải có entropy thấp."""
        iq = make_tone_iq(n=4096)
        psd = sdr.compute_psd(iq)
        ent = sdr.spectral_entropy(psd)
        self.assertLess(ent, 0.4, "Single tone should have low spectral entropy")

    def test_noise_has_high_entropy(self):
        iq = make_noise_iq(n=4096)
        psd = sdr.compute_psd(iq)
        ent = sdr.spectral_entropy(psd)
        self.assertGreater(ent, 0.7, "White noise should have high spectral entropy")

    def test_burst_has_high_kurtosis(self):
        iq = make_burst_iq()
        kurt = sdr.kurtosis_of(iq)
        self.assertGreater(kurt, 10.0, "Burst signal should have kurtosis >> 3")


# ===========================================================================
# TestDSP — hàm xử lý tín hiệu số
# ===========================================================================

class TestDSP(unittest.TestCase):

    # ---- iq_bytes_to_complex ------------------------------------------------

    def test_iq_bytes_empty_returns_zero_array(self):
        out = sdr.iq_bytes_to_complex(b"")
        self.assertEqual(len(out), 0)

    def test_iq_bytes_none_returns_zero_array(self):
        out = sdr.iq_bytes_to_complex(None)
        self.assertEqual(len(out), 0)

    def test_iq_bytes_odd_length_drops_last_byte(self):
        """Số byte lẻ: byte cuối bị bỏ để tránh IQ mismatch."""
        data = bytes([10, 20, 30])  # 3 bytes → drop 1 → 1 sample
        out = sdr.iq_bytes_to_complex(data)
        self.assertEqual(len(out), 1)
        self.assertAlmostEqual(out[0].real, 10.0)
        self.assertAlmostEqual(out[0].imag, 20.0)

    def test_iq_bytes_interleaved_iq(self):
        """Format: [I0, Q0, I1, Q1, ...]"""
        data = bytes([10, 20, 30, 40])  # I0=10,Q0=20, I1=30,Q1=40
        out = sdr.iq_bytes_to_complex(data)
        self.assertEqual(len(out), 2)
        self.assertAlmostEqual(out[0].real, 10.0)
        self.assertAlmostEqual(out[0].imag, 20.0)
        self.assertAlmostEqual(out[1].real, 30.0)
        self.assertAlmostEqual(out[1].imag, 40.0)

    def test_iq_bytes_dtype(self):
        data = bytes([0, 0, 50, 50])
        out = sdr.iq_bytes_to_complex(data)
        self.assertEqual(out.dtype, np.complex64)

    # ---- estimate_power_dbm ------------------------------------------------

    def test_power_empty_returns_floor(self):
        self.assertAlmostEqual(sdr.estimate_power_dbm(make_empty_iq()), -120.0)

    def test_power_none_returns_floor(self):
        self.assertAlmostEqual(sdr.estimate_power_dbm(None), -120.0)

    def test_power_increases_with_amplitude(self):
        low  = sdr.estimate_power_dbm(make_noise_iq(amplitude=10.0))
        high = sdr.estimate_power_dbm(make_noise_iq(amplitude=100.0))
        self.assertGreater(high, low)

    def test_power_is_float(self):
        p = sdr.estimate_power_dbm(make_noise_iq())
        self.assertIsInstance(p, float)

    def test_power_reasonable_range(self):
        """Amplitude=50 (mid-range 8-bit) → power khoảng -10 đến +10 dBm."""
        p = sdr.estimate_power_dbm(make_noise_iq(amplitude=50.0))
        self.assertGreater(p, -50.0)
        self.assertLess(p, 50.0)

    # ---- compute_psd -------------------------------------------------------

    def test_psd_empty_returns_zeros(self):
        psd = sdr.compute_psd(make_empty_iq())
        self.assertTrue(np.all(psd == 0))

    def test_psd_too_short_returns_zeros(self):
        iq = make_noise_iq(n=10)   # < FFT_SIZE (1024)
        psd = sdr.compute_psd(iq)
        self.assertTrue(np.all(psd == 0))

    def test_psd_shape(self):
        """IQ phức → phổ hai phía (fftshift) đủ FFT_SIZE bin.

        (Test cũ đòi FFT_SIZE//2 — đúng cho tín hiệu thực/rfft, sai cho baseband phức;
        find_signal_peaks() dùng len(psd) với fftfreq nên FFT_SIZE mới là hợp đồng đúng.)
        """
        iq = make_noise_iq(n=4096)
        psd = sdr.compute_psd(iq)
        self.assertEqual(psd.shape, (sdr.FFT_SIZE,))

    def test_psd_short_input_has_same_shape_as_normal(self):
        """Nhánh 'đầu vào quá ngắn' từng trả FFT_SIZE//2 bin, khác nhánh thường."""
        short = sdr.compute_psd(make_noise_iq(n=10))
        normal = sdr.compute_psd(make_noise_iq(n=4096))
        self.assertEqual(short.shape, normal.shape)
        self.assertEqual(sdr.compute_psd(None).shape, normal.shape)

    def test_psd_dtype(self):
        iq = make_noise_iq(n=4096)
        psd = sdr.compute_psd(iq)
        self.assertEqual(psd.dtype, np.float32)

    def test_psd_nonnegative(self):
        psd = sdr.compute_psd(make_noise_iq())
        self.assertTrue(np.all(psd >= 0))

    def test_psd_tone_has_peak(self):
        """Sóng sin → PSD có peak rõ, không flat."""
        iq = make_tone_iq(n=4096)
        psd = sdr.compute_psd(iq)
        ratio = psd.max() / (psd.mean() + 1e-9)
        self.assertGreater(ratio, 10.0, "Tone PSD should have a sharp peak")

    # ---- spectral_entropy --------------------------------------------------

    def test_entropy_zero_psd_returns_zero(self):
        self.assertAlmostEqual(sdr.spectral_entropy(np.zeros(512)), 0.0)

    def test_entropy_flat_psd_returns_one(self):
        """Uniform distribution → max entropy = 1.0."""
        psd = np.ones(512)
        ent = sdr.spectral_entropy(psd)
        self.assertAlmostEqual(ent, 1.0, places=4)

    def test_entropy_impulse_psd_returns_zero(self):
        """Tất cả năng lượng tại 1 bin → entropy gần 0."""
        psd = np.zeros(512)
        psd[256] = 1.0
        ent = sdr.spectral_entropy(psd)
        self.assertAlmostEqual(ent, 0.0, places=4)

    def test_entropy_in_range(self):
        psd = sdr.compute_psd(make_noise_iq())
        ent = sdr.spectral_entropy(psd)
        self.assertGreaterEqual(ent, 0.0)
        self.assertLessEqual(ent, 1.0)

    def test_entropy_single_bin_psd(self):
        """psd có 1 phần tử → log2(n) undefined (n<=1) → return 0."""
        self.assertAlmostEqual(sdr.spectral_entropy(np.array([5.0])), 0.0)

    # ---- kurtosis_of -------------------------------------------------------

    def test_kurtosis_none_returns_zero(self):
        self.assertAlmostEqual(sdr.kurtosis_of(None), 0.0)

    def test_kurtosis_short_returns_zero(self):
        self.assertAlmostEqual(sdr.kurtosis_of(np.ones(5, dtype=np.complex64)), 0.0)

    def test_kurtosis_constant_returns_zero(self):
        """Constant signal → std=0 → return 0 (guard division by zero)."""
        iq = np.ones(1024, dtype=np.complex64) * 50.0
        self.assertAlmostEqual(sdr.kurtosis_of(iq), 0.0)

    def test_kurtosis_gaussian_envelope_is_rayleigh(self):
        """kurtosis_of() đo kurtosis của ĐƯỜNG BAO |IQ|, không phải của I hoặc Q riêng lẻ.

        Nhiễu Gauss phức có đường bao Rayleigh, kurtosis (không trừ 3) là
        (32 - 3π²) / (4 - π)² ≈ 3.245 — không phải 3 (con số 3 chỉ đúng cho I hoặc Q).
        Kỳ vọng cũ "≈ 3 ± 0.2" sai lý thuyết; hàm đúng, test sai.
        """
        rng = np.random.default_rng(0)
        iq = (rng.standard_normal(100000) + 1j * rng.standard_normal(100000)).astype(np.complex64)
        rayleigh = (32 - 3 * math.pi ** 2) / (4 - math.pi) ** 2
        self.assertAlmostEqual(rayleigh, 3.245, places=3)
        self.assertAlmostEqual(sdr.kurtosis_of(iq), rayleigh, delta=0.1)

    def test_kurtosis_of_i_component_alone_is_three(self):
        """Đối chứng: kurtosis của MỘT thành phần Gauss thực đúng là ≈ 3."""
        rng = np.random.default_rng(0)
        x = rng.standard_normal(200000)
        self.assertAlmostEqual(float(np.mean(((x - x.mean()) / x.std()) ** 4)), 3.0, delta=0.1)

    def test_kurtosis_burst_greater_than_noise(self):
        noise = sdr.kurtosis_of(make_noise_iq())
        burst = sdr.kurtosis_of(make_burst_iq())
        self.assertGreater(burst, noise)

    # ---- stft_entropy ------------------------------------------------------

    def test_stft_entropy_empty_returns_zero(self):
        self.assertAlmostEqual(sdr.stft_entropy(make_empty_iq()), 0.0)

    def test_stft_entropy_too_short_returns_zero(self):
        iq = make_noise_iq(n=10)
        self.assertAlmostEqual(sdr.stft_entropy(iq), 0.0)

    def test_stft_entropy_positive(self):
        iq = make_noise_iq(n=4096)
        self.assertGreater(sdr.stft_entropy(iq), 0.0)

    def test_stft_entropy_noise_greater_than_tone(self):
        """Noise có STFT entropy cao hơn single tone."""
        noise_e = sdr.stft_entropy(make_noise_iq(n=4096))
        tone_e  = sdr.stft_entropy(make_tone_iq(n=4096))
        self.assertGreater(noise_e, tone_e)

    # ---- cyclostationary_score ---------------------------------------------

    def test_cyclo_empty_returns_zero(self):
        self.assertAlmostEqual(sdr.cyclostationary_score(make_empty_iq()), 0.0)

    def test_cyclo_short_returns_zero(self):
        iq = make_noise_iq(n=100)
        self.assertAlmostEqual(sdr.cyclostationary_score(iq), 0.0)

    def test_cyclo_in_range(self):
        score = sdr.cyclostationary_score(make_noise_iq(n=8192))
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_cyclo_periodic_greater_than_noise(self):
        """Tín hiệu lặp có score cao hơn white noise."""
        noise_score = sdr.cyclostationary_score(make_noise_iq(n=8192))
        repeating_score = sdr.cyclostationary_score(make_repeating_iq())
        self.assertGreater(repeating_score, noise_score)

    # ---- detect_single_carrier ---------------------------------------------

    def test_single_carrier_none_returns_false(self):
        self.assertFalse(sdr.detect_single_carrier(None))

    def test_single_carrier_short_returns_false(self):
        self.assertFalse(sdr.detect_single_carrier(np.ones(3)))

    def test_single_carrier_tone_returns_true(self):
        iq = make_tone_iq(n=4096)
        psd = sdr.compute_psd(iq)
        self.assertTrue(sdr.detect_single_carrier(psd))

    def test_single_carrier_noise_returns_false(self):
        iq = make_noise_iq(n=4096)
        psd = sdr.compute_psd(iq)
        self.assertFalse(sdr.detect_single_carrier(psd))

    def test_single_carrier_noise_never_flagged_any_averaging(self):
        """Nhiễu thuần KHÔNG được là 'carrier' — kể cả PSD chỉ 1 đoạn (n=1024, xấu nhất).

        Bản cũ chỉ kiểm 'không quá vài bin trên mean+4σ' → 0 bin cũng thỏa → nhiễu bị gán
        single_carrier=True (cờ này còn đi vào feature của classifier).
        """
        for n, seeds in ((1024, 40), (4096, 60), (32768, 60)):
            for seed in range(seeds):
                psd = sdr.compute_psd(make_noise_iq(n=n, seed=seed))
                self.assertFalse(sdr.detect_single_carrier(psd), f"n={n} seed={seed}")

    def test_single_carrier_tone_buried_in_noise_returns_true(self):
        fs = 2e6
        t = np.arange(4096) / fs
        rng = np.random.default_rng(1)
        iq = (20 * np.exp(2j * np.pi * 100e3 * t)
              + 50 * (rng.standard_normal(4096) + 1j * rng.standard_normal(4096))
              ).astype(np.complex64)
        self.assertTrue(sdr.detect_single_carrier(sdr.compute_psd(iq)))

    def test_single_carrier_zero_spectrum_returns_false(self):
        self.assertFalse(sdr.detect_single_carrier(np.zeros(sdr.FFT_SIZE)))

    def test_single_carrier_wideband_plateau_returns_false(self):
        """Khối rộng đều (30% bin) mạnh nhưng không bin nào vượt mean+4σ → không phải carrier."""
        p = np.ones(sdr.FFT_SIZE)
        p[:300] = 100.0
        self.assertFalse(sdr.detect_single_carrier(p))

    def test_single_carrier_isolated_line_returns_true(self):
        p = np.full(sdr.FFT_SIZE, 1e-3)
        p[sdr.FFT_SIZE // 2] = 1.0
        self.assertTrue(sdr.detect_single_carrier(p))

    # ---- gsm_fcch_score ----------------------------------------------------

    def test_fcch_empty_returns_zero(self):
        self.assertAlmostEqual(sdr.gsm_fcch_score(make_empty_iq()), 0.0)

    def test_fcch_short_returns_zero(self):
        self.assertAlmostEqual(sdr.gsm_fcch_score(make_noise_iq(n=100)), 0.0)

    def test_fcch_in_range(self):
        score = sdr.gsm_fcch_score(make_noise_iq(n=4096))
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_fcch_tone_at_67700hz_has_high_score(self):
        """GSM FCCH = sinusoid tại ~67.7 kHz → score cao."""
        iq = make_tone_iq(n=4096, freq_hz=67700.0, fs=sdr.SAMPLE_RATE_HZ, amplitude=127.0)
        score = sdr.gsm_fcch_score(iq)
        self.assertGreater(score, 0.1, "FCCH tone should score higher than noise")

    # ---- get_calibration_offset --------------------------------------------

    def test_calibration_offset_in_range(self):
        """Offset tồn tại trong tất cả các băng tần trong CALIBRATION_BANDS."""
        for lo, hi, expected in sdr.CALIBRATION_BANDS:
            mid = (lo + hi) / 2.0
            offset = sdr.get_calibration_offset(mid)
            self.assertIsInstance(offset, float)

    def test_calibration_offset_out_of_range_uses_default(self):
        """Tần số ngoài tất cả bands → fallback -50.0 dB."""
        offset = sdr.get_calibration_offset(100e9)   # 100 GHz, ngoài range
        self.assertAlmostEqual(offset, -50.0)


# ===========================================================================
# TestChannel — Channel baseline tracking
# ===========================================================================

class TestChannel(unittest.TestCase):

    def _make_ch(self) -> sdr.Channel:
        return sdr.Channel("TEST", 433.92e6, 2, "IOT_REPLAY")

    def test_baseline_empty_returns_floor(self):
        ch = self._make_ch()
        self.assertAlmostEqual(ch.baseline, -100.0)

    def test_std_empty_returns_one(self):
        ch = self._make_ch()
        self.assertAlmostEqual(ch.std, 1.0)

    def test_baseline_is_median(self):
        ch = self._make_ch()
        for v in [-70, -60, -80, -65, -55]:
            ch.add_sample(v)
        expected = float(np.median([-70, -60, -80, -65, -55]))
        self.assertAlmostEqual(ch.baseline, expected)

    def test_zscore_at_baseline_is_zero(self):
        ch = self._make_ch()
        for _ in range(10):
            ch.add_sample(-70.0)
        self.assertAlmostEqual(ch.zscore(-70.0), 0.0, places=3)

    def test_zscore_above_baseline_is_positive(self):
        ch = self._make_ch()
        for _ in range(20):
            ch.add_sample(-70.0)
        self.assertGreater(ch.zscore(-50.0), 0.0)

    def test_update_baseline_absorbs_normal(self):
        """z-score khoảng 0 → sample được add vào history."""
        ch = self._make_ch()
        for _ in range(20):
            ch.add_sample(-70.0)
        before = len(ch._history)
        ch.update_baseline(-70.5)   # gần median → z nhỏ → được thêm
        self.assertEqual(len(ch._history), before + 1)

    def test_update_baseline_skips_alert(self):
        """Alert sample (z > POWER_Z_ALERT) KHÔNG được add vào baseline."""
        ch = self._make_ch()
        for _ in range(20):
            ch.add_sample(-70.0)
        hist_before = list(ch._history)
        ch.update_baseline(-30.0)   # z >> POWER_Z_ALERT → skip
        # History không thay đổi
        self.assertEqual(list(ch._history), hist_before)

    def test_history_capped_at_max_samples(self):
        ch = self._make_ch()
        limit = sdr.Channel.BASELINE_MAX_SAMPLES
        for i in range(limit + 50):
            ch.add_sample(float(-70 + i * 0.01))
        self.assertEqual(len(ch._history), limit)

    def test_std_nonnegative(self):
        ch = self._make_ch()
        for v in [-70.0, -71.0, -69.0, -72.0]:
            ch.add_sample(v)
        self.assertGreaterEqual(ch.std, 0.0)

    def test_std_constant_signal_returns_floor(self):
        """std = 0 → clamp to 1e-6 → return 1.0 (floor guard)."""
        ch = self._make_ch()
        for _ in range(10):
            ch.add_sample(-70.0)
        # std là 0 → code trả về 1.0
        self.assertAlmostEqual(ch.std, 1.0)


# ===========================================================================
# TestThreatRules — Logic phân loại threat trong analyze()
# ===========================================================================

class TestThreatRules(unittest.TestCase):

    def _analyze(self, threat_type: str, channel_name: str = "TEST",
                 freq_hz: float = 435e6, **anomaly_overrides) -> sdr.ThreatResult:
        ch = sdr.Channel(channel_name, freq_hz, 1, threat_type)
        for _ in range(20):
            ch.add_sample(-70.0)
        r = make_dummy_anomaly_result(
            channel=channel_name, freq_hz=freq_hz,
            threat_type=threat_type, **anomaly_overrides
        )
        return sdr.analyze(ch, r, {})

    # ---- OK baseline -------------------------------------------------------

    def test_no_alerts_returns_ok(self):
        res = self._analyze("GPS_JAM")
        self.assertEqual(res.threat_level, sdr.ThreatLevel.OK)

    # ---- GPS_JAM -----------------------------------------------------------

    def test_gps_jam_power_and_entropy_alert_is_critical(self):
        res = self._analyze("GPS_JAM", power_alert=True, entropy_alert=True)
        self.assertEqual(res.threat_level, sdr.ThreatLevel.CRITICAL)

    def test_gps_jam_power_only_is_high(self):
        res = self._analyze("GPS_JAM", power_alert=True, entropy_alert=False)
        self.assertEqual(res.threat_level, sdr.ThreatLevel.HIGH)

    def test_gps_jam_entropy_only_stays_low(self):
        """Entropy alert saja (không có power alert) → GPS rule không fire."""
        res = self._analyze("GPS_JAM", power_alert=False, entropy_alert=True)
        self.assertLessEqual(res.threat_level.value, sdr.ThreatLevel.LOW.value)

    # ---- FAKE_BTS ----------------------------------------------------------

    def test_fake_bts_gsm_fcch_high_score_is_high(self):
        res = self._analyze("FAKE_BTS", gsm_fcch=0.5)
        self.assertGreaterEqual(res.threat_level.value, sdr.ThreatLevel.HIGH.value)

    def test_fake_bts_structural_alert_is_critical(self):
        res = self._analyze("FAKE_BTS", structural_alert=True, entropy=0.3, single_carrier=True)
        self.assertEqual(res.threat_level, sdr.ThreatLevel.CRITICAL)

    def test_fake_bts_no_alerts_is_ok(self):
        res = self._analyze("FAKE_BTS")
        self.assertEqual(res.threat_level, sdr.ThreatLevel.OK)

    # ---- CELL_JAM ----------------------------------------------------------

    def test_cell_jam_power_and_burst_is_critical(self):
        res = self._analyze("CELL_JAM", power_alert=True, burst_alert=True)
        self.assertEqual(res.threat_level, sdr.ThreatLevel.CRITICAL)

    def test_cell_jam_power_only_stays_low(self):
        res = self._analyze("CELL_JAM", power_alert=True, burst_alert=False)
        self.assertLessEqual(res.threat_level.value, sdr.ThreatLevel.LOW.value)

    # ---- DRONE_FHSS --------------------------------------------------------

    def test_drone_fhss_swept_alert_is_high(self):
        res = self._analyze("DRONE_FHSS", swept_alert=True)
        self.assertGreaterEqual(res.threat_level.value, sdr.ThreatLevel.HIGH.value)

    def test_drone_fhss_type_ai_alert_is_high(self):
        res = self._analyze("DRONE_FHSS", type_ai_alert=True, type_ai_score=0.9)
        self.assertGreaterEqual(res.threat_level.value, sdr.ThreatLevel.HIGH.value)

    # ---- WIFI_DEAUTH -------------------------------------------------------

    def test_wifi_deauth_burst_and_power_is_medium(self):
        res = self._analyze("WIFI_DEAUTH", burst_alert=True, power_alert=True)
        self.assertEqual(res.threat_level, sdr.ThreatLevel.MEDIUM)

    # ---- EMERGENCY ---------------------------------------------------------

    def test_emergency_any_alert_is_high(self):
        """Emergency channel: bất kỳ alert nào cũng là HIGH."""
        res = self._analyze("EMERGENCY", power_alert=True)
        self.assertGreaterEqual(res.threat_level.value, sdr.ThreatLevel.HIGH.value)

    # ---- AI consensus ------------------------------------------------------

    def test_ai_both_agree_escalates_to_high(self):
        res = self._analyze("IOT_REPLAY",
                            hybrid_ai_alert=True, hybrid_ai_score=0.8,
                            type_ai_alert=True,   type_ai_score=0.8)
        self.assertGreaterEqual(res.threat_level.value, sdr.ThreatLevel.HIGH.value)

    def test_only_one_ai_does_not_escalate(self):
        """Chỉ 1 AI alert → không reach HIGH qua ai_both_agree path."""
        res = self._analyze("IOT_REPLAY",
                            hybrid_ai_alert=True, hybrid_ai_score=0.8,
                            type_ai_alert=False,  type_ai_score=0.0)
        # Chỉ reach LOW (any_alert=True qua hybrid_ai_alert)
        self.assertLessEqual(res.threat_level.value, sdr.ThreatLevel.LOW.value)

    # ---- indicators --------------------------------------------------------

    def test_indicators_list_present(self):
        res = self._analyze("GPS_JAM", power_alert=True, entropy_alert=True)
        self.assertIsInstance(res.indicators, list)
        self.assertGreater(len(res.indicators), 0)

    def test_ok_result_has_empty_or_minimal_indicators(self):
        res = self._analyze("GPS_JAM")
        # OK result: không có indicators
        self.assertEqual(res.threat_level, sdr.ThreatLevel.OK)

    # ---- result fields -----------------------------------------------------

    def test_result_has_timestamp(self):
        res = self._analyze("GPS_JAM")
        self.assertIsNotNone(res.timestamp)
        self.assertTrue(len(res.timestamp) > 0)

    def test_result_confidence_nonnegative(self):
        res = self._analyze("GPS_JAM", hybrid_ai_score=0.7)
        self.assertGreaterEqual(res.confidence, 0.0)
        self.assertLessEqual(res.confidence, 1.0)


# ===========================================================================
# TestConfidenceGates
# ===========================================================================

class TestConfidenceGates(unittest.TestCase):

    # ---- PersistenceTracker ------------------------------------------------

    def test_persistence_not_triggered_below_min(self):
        pt = sdr.PersistenceTracker()
        for _ in range(sdr.PERSISTENCE_MIN_COUNT - 1):
            pt.record("GPS_L1", True)
        self.assertFalse(pt.is_persistent("GPS_L1"))

    def test_persistence_triggered_at_min_count(self):
        pt = sdr.PersistenceTracker()
        for _ in range(sdr.PERSISTENCE_MIN_COUNT):
            pt.record("GPS_L1", True)
        self.assertTrue(pt.is_persistent("GPS_L1"))

    def test_persistence_window_slides_correctly(self):
        """Sau PERSISTENCE_WINDOW alerts, cửa sổ trượt."""
        pt = sdr.PersistenceTracker()
        w = sdr.PERSISTENCE_WINDOW
        # Fill window với True
        for _ in range(w):
            pt.record("CH", True)
        self.assertTrue(pt.is_persistent("CH"))
        # Append False × w để đẩy tất cả True ra khỏi window
        for _ in range(w):
            pt.record("CH", False)
        self.assertFalse(pt.is_persistent("CH"))

    def test_persistence_independent_channels(self):
        pt = sdr.PersistenceTracker()
        for _ in range(sdr.PERSISTENCE_MIN_COUNT):
            pt.record("CH_A", True)
        # CH_B chưa record gì
        self.assertTrue(pt.is_persistent("CH_A"))
        self.assertFalse(pt.is_persistent("CH_B"))

    def test_count_returns_number_of_alerts_in_window(self):
        pt = sdr.PersistenceTracker()
        pt.record("CH", True)
        pt.record("CH", False)
        pt.record("CH", True)
        self.assertEqual(pt.count("CH"), 2)

    # ---- apply_confidence_gate (không có RF) --------------------------------

    def _make_result(self, level: sdr.ThreatLevel, **anomaly_overrides) -> sdr.ThreatResult:
        anomaly = make_dummy_anomaly_result(**anomaly_overrides)
        return sdr.ThreatResult(
            channel="GPS_L1", freq_hz=1575.42e6,
            threat_type="GPS_JAM", threat_level=level,
            anomaly=anomaly, indicators=[], timestamp="2024-01-01T00:00:00Z",
        )

    def test_gate_persist_downgrades_non_persistent_high(self):
        """HIGH nhưng không persistent → downgrade về MEDIUM."""
        res = self._make_result(sdr.ThreatLevel.HIGH)
        sdr.apply_confidence_gate(res, is_persistent=False, persist_count=1)
        self.assertEqual(res.threat_level, sdr.ThreatLevel.MEDIUM)

    def test_gate_persist_keeps_high_if_persistent(self):
        res = self._make_result(sdr.ThreatLevel.HIGH)
        sdr.apply_confidence_gate(res, is_persistent=True, persist_count=3)
        self.assertEqual(res.threat_level, sdr.ThreatLevel.HIGH)

    def test_gate_critical_requires_ai_consensus_and_zscore(self):
        """CRITICAL không có AI consensus + z thấp → downgrade về HIGH."""
        res = self._make_result(
            sdr.ThreatLevel.CRITICAL,
            hybrid_ai_alert=False, type_ai_alert=False, zscore=2.0
        )
        sdr.apply_confidence_gate(res, is_persistent=True, persist_count=5)
        self.assertEqual(res.threat_level, sdr.ThreatLevel.HIGH)

    def test_gate_critical_passes_with_consensus_and_high_zscore(self):
        """CRITICAL có AI consensus + |z| > CRITICAL_ZSCORE_GATE → giữ CRITICAL."""
        res = self._make_result(
            sdr.ThreatLevel.CRITICAL,
            hybrid_ai_alert=True, type_ai_alert=True,
            zscore=sdr.CRITICAL_ZSCORE_GATE + 0.5
        )
        sdr.apply_confidence_gate(res, is_persistent=True, persist_count=5)
        self.assertEqual(res.threat_level, sdr.ThreatLevel.CRITICAL)

    def test_gate_medium_not_affected_by_persistence_gate(self):
        """Gate 1 (persistence) chỉ áp dụng cho >= HIGH."""
        res = self._make_result(sdr.ThreatLevel.MEDIUM)
        sdr.apply_confidence_gate(res, is_persistent=False, persist_count=0)
        self.assertEqual(res.threat_level, sdr.ThreatLevel.MEDIUM)

    def test_gate_ok_unchanged(self):
        res = self._make_result(sdr.ThreatLevel.OK)
        sdr.apply_confidence_gate(res, is_persistent=False, persist_count=0)
        self.assertEqual(res.threat_level, sdr.ThreatLevel.OK)


# ===========================================================================
# TestRXGuard — ReceiveOnlySDRProxy chặn TX calls
# ===========================================================================

class TestRXGuard(unittest.TestCase):

    class FakeSDR:
        """Mock SDR object — RX methods + các thành viên TX mà guard phải chặn."""
        def __init__(self):
            self.sample_rate = 2e6
            self.center_freq = 433e6
        def start_rx(self):
            return "rx_started"
        def read_samples(self, n):
            return np.zeros(n, dtype=np.int8)
        # TX-capable members a real HackRF binding exposes.  The tests below mock
        # os._exit (so the process survives) and then the guard falls through to
        # getattr(self._sdr, name) — without these the fixture raised AttributeError
        # before the assertion ran.  In production os._exit never returns.
        def transmit(self): return "SHOULD_NEVER_RUN"
        def start_tx(self): return "SHOULD_NEVER_RUN"
        def send_samples(self, *a): return "SHOULD_NEVER_RUN"
        def tx_vga(self): return "SHOULD_NEVER_RUN"
        def jam(self): return "SHOULD_NEVER_RUN"
        def replay_signal(self): return "SHOULD_NEVER_RUN"

    def _wrap(self) -> sdr.ReceiveOnlySDRProxy:
        return sdr.ReceiveOnlySDRProxy(self.FakeSDR())

    def test_rx_method_passthrough(self):
        """RX call (start_rx) phải pass through bình thường."""
        proxy = self._wrap()
        result = proxy.start_rx()
        self.assertEqual(result, "rx_started")

    def test_rx_attribute_passthrough(self):
        proxy = self._wrap()
        self.assertAlmostEqual(proxy.sample_rate, 2e6)

    def test_read_samples_passthrough(self):
        proxy = self._wrap()
        samples = proxy.read_samples(16)
        self.assertEqual(len(samples), 16)

    def test_transmit_blocked_calls_exit(self):
        """Bất kỳ TX call nào → gọi os._exit(1)."""
        proxy = self._wrap()
        with mock.patch("os._exit") as mock_exit:
            # __getattr__ gọi _blocked → os._exit(1)
            _ = proxy.transmit
            mock_exit.assert_called_once_with(1)

    def test_start_tx_blocked(self):
        proxy = self._wrap()
        with mock.patch("os._exit") as mock_exit:
            _ = proxy.start_tx
            mock_exit.assert_called_once_with(1)

    def test_send_samples_blocked(self):
        proxy = self._wrap()
        with mock.patch("os._exit") as mock_exit:
            _ = proxy.send_samples
            mock_exit.assert_called_once_with(1)

    def test_tx_vga_blocked(self):
        proxy = self._wrap()
        with mock.patch("os._exit") as mock_exit:
            _ = proxy.tx_vga
            mock_exit.assert_called_once_with(1)

    def test_jam_method_blocked(self):
        proxy = self._wrap()
        with mock.patch("os._exit") as mock_exit:
            _ = proxy.jam
            mock_exit.assert_called_once_with(1)

    def test_replay_blocked(self):
        proxy = self._wrap()
        with mock.patch("os._exit") as mock_exit:
            _ = proxy.replay_signal
            mock_exit.assert_called_once_with(1)

    def test_block_message_still_printed_when_logger_fails(self):
        """logger.critical hỏng thì phải BÁO là nó hỏng (stderr), thông điệp chặn vẫn được in."""
        proxy = self._wrap()
        buf = io.StringIO()
        with mock.patch("os._exit") as mock_exit, \
                mock.patch.object(sdr.logger, "critical", side_effect=RuntimeError("log dead")), \
                contextlib.redirect_stderr(buf):
            _ = proxy.transmit
        mock_exit.assert_called_once_with(1)
        out = buf.getvalue()
        self.assertIn("BI CHAN", out)
        self.assertIn("logger.critical that bai", out)
        self.assertIn("log dead", out)

    def test_integrity_check_refuses_to_start_and_reports_even_if_logger_fails(self):
        """verify_rx_guard_integrity.fail(): connect_hackrf khong boc proxy => TU CHOI KHOI DONG.
        Thông điệp phải tới stderr kể cả khi logger.critical hỏng, và lỗi logger cũng phải hiện."""
        def connect_without_proxy():
            # NB: guard tìm tên lớp proxy trong *source* của hàm này (kể cả comment!),
            # nên không được nhắc tên đó ở đây.
            return None
        buf = io.StringIO()
        with mock.patch.object(sdr, "connect_hackrf", connect_without_proxy), \
                mock.patch.object(sdr.logger, "critical", side_effect=RuntimeError("log dead")), \
                contextlib.redirect_stderr(buf):
            with self.assertRaises(SystemExit) as cm:
                sdr.verify_rx_guard_integrity()
        self.assertEqual(cm.exception.code, 1)
        out = buf.getvalue()
        self.assertIn("KIEM TRA TOAN VEN THAT BAI", out)
        self.assertIn("TU CHOI KHOI DONG", out)
        # Phải đếm CHÍNH XÁC, không chỉ assertIn: bước 2 của self-test cũng đi qua
        # ReceiveOnlySDRProxy._blocked() và tự in đúng câu này một lần. Lần thứ hai
        # mới là của fail() — thiếu nó thì count == 1 và test đỏ.
        self.assertEqual(out.count("logger.critical that bai"), 2)

    def test_setattr_tx_blocked(self):
        """Gán vào attribute TX → cũng bị chặn."""
        proxy = self._wrap()
        with mock.patch("os._exit") as mock_exit:
            proxy.tx_gain = 40
            mock_exit.assert_called_once_with(1)

    def test_setattr_rx_passes_through(self):
        """Gán vào attribute thường → không block."""
        proxy = self._wrap()
        with mock.patch("os._exit") as mock_exit:
            proxy.sample_rate = 4e6
            mock_exit.assert_not_called()
        self.assertAlmostEqual(proxy._sdr.sample_rate, 4e6)

    def test_looks_like_tx_patterns(self):
        """_looks_like_tx() nhận biết đúng các patterns."""
        should_block = [
            "transmit", "start_tx", "tx_start", "send_samples",
            "write_samples", "tx_enable", "enable_tx", "set_tx",
            "tx_vga", "txvga", "tx_gain", "tx_amp", "repeat",
            "replay", "jam", "spoof_tx", "carrier_on",
            "TRANSMIT",    # case-insensitive
            "Start_TX",
        ]
        for name in should_block:
            with self.subTest(name=name):
                self.assertTrue(sdr._looks_like_tx(name))

    def test_looks_like_tx_allows_rx_names(self):
        """RX method names KHÔNG bị flag là TX."""
        rx_names = ["start_rx", "read_samples", "tune", "snapshot",
                    "sample_rate", "center_freq", "lna_gain", "vga_gain"]
        for name in rx_names:
            with self.subTest(name=name):
                self.assertFalse(sdr._looks_like_tx(name))


# ===========================================================================
# TestRFClassifier — Training guards
# ===========================================================================

class TestRFClassifier(unittest.TestCase):

    def _make_clf(self, model_path=None) -> sdr.RFThreatClassifier:
        if model_path is None:
            model_path = os.path.join(tempfile.mkdtemp(), "test_rf.joblib")
        return sdr.RFThreatClassifier(model_path=model_path)

    # Mỗi lớp có "chữ ký" riêng (công suất / z-score / SNR / tần số) nhưng các lớp CHỒNG LẤN
    # một phần, giống nhãn thật do analyst gắn.  Hai cực đoan đều sai:
    #   * bản cũ bốc từng feature độc lập với nhãn → nhãn ngẫu nhiên, mô hình không có gì để
    #     học: test "train thành công" chỉ pass nhờ may, test predict tự SKIP vì 'degenerate';
    #   * lớp tách hoàn hảo → cv5 ≈ 1.0 > RF_RULE_TABLE_CEILING (0.97): train() từ chối có chủ
    #     đích vì nghi "nhãn = luật", đúng thiết kế (Fix [3]).
    # Nhiễu ×3 + chỉ 70% mẫu nằm trên tần số riêng của lớp cho cv5 ≈ 0.83–0.85 (đo bằng
    # train() thật), xa cả trần 0.97 lẫn baseline đa số.
    _NOISE = 3.0
    _P_OWN_FREQ = 0.7
    _ALL_FREQS = (433e6, 868e6, 915e6, 1575e6)
    _CLASS_SIGNATURE = {
        "GPS_JAM":    dict(power=-30.0, z=8.0, snr=25.0, freq=1575e6),
        "FAKE_BTS":   dict(power=-55.0, z=3.0, snr=12.0, freq=915e6),
        "CELL_JAM":   dict(power=-42.0, z=6.0, snr=18.0, freq=868e6),
        "IOT_REPLAY": dict(power=-70.0, z=0.0, snr=5.0,  freq=433e6),
    }

    def _fake_db_rows(self, n_per_class: dict) -> list:
        """Tạo labeled rows giả cho training (lớp tách được, xem _CLASS_SIGNATURE)."""
        rows = []
        rng = np.random.default_rng(99)
        for label, count in n_per_class.items():
            sig = self._CLASS_SIGNATURE[label]
            k = self._NOISE
            for i in range(count):
                own = rng.random() < self._P_OWN_FREQ
                rows.append({
                    "threat_type": label,
                    "power_dbm":   sig["power"] + float(rng.normal(0, 4.0 * k)),
                    "zscore":      sig["z"] + float(rng.normal(0, 0.8 * k)),
                    "snr_db":      sig["snr"] + float(rng.normal(0, 2.5 * k)),
                    "bandwidth_hz": 2e6,
                    "duration_ms": 5.0,
                    "persistence_ratio": float(rng.uniform(0, 1)),   # nhiễu thuần, không mang thông tin
                    "freq_hz":     sig["freq"] if own else float(rng.choice(self._ALL_FREQS)),
                    "confirmed":   1,
                })
        return rows

    def test_new_clf_not_usable(self):
        clf = self._make_clf()
        self.assertFalse(clf.usable)

    def test_train_refuses_below_min_samples(self):
        clf = self._make_clf()
        rows = self._fake_db_rows({"GPS_JAM": 10, "FAKE_BTS": 10})
        with mock.patch.object(sdr, "db_fetch_labeled_events", return_value=rows):
            result = clf.train()
        self.assertFalse(result)
        self.assertFalse(clf.usable)

    def test_train_refuses_single_class(self):
        """Chỉ có 1 class → từ chối training."""
        clf = self._make_clf()
        rows = self._fake_db_rows({"GPS_JAM": 250})
        with mock.patch.object(sdr, "db_fetch_labeled_events", return_value=rows):
            result = clf.train()
        self.assertFalse(result)

    def test_train_refuses_imbalanced_labels(self):
        """1 class chiếm >85% → từ chối vì nghi ngờ label theo rule."""
        clf = self._make_clf()
        rows = self._fake_db_rows({"GPS_JAM": 180, "FAKE_BTS": 20})
        # 180/200 = 90% > RF_MAX_CLASS_SHARE (0.85)
        with mock.patch.object(sdr, "db_fetch_labeled_events", return_value=rows):
            result = clf.train()
        self.assertFalse(result)
        self.assertFalse(clf.usable)

    def test_train_succeeds_balanced_data(self):
        """Data cân bằng, đủ samples → training thành công."""
        clf = self._make_clf()
        rows = self._fake_db_rows({
            "GPS_JAM": 100, "FAKE_BTS": 100, "CELL_JAM": 80, "IOT_REPLAY": 80
        })
        with mock.patch.object(sdr, "db_fetch_labeled_events", return_value=rows):
            with mock.patch.object(clf, "_save"):  # skip lưu file
                result = clf.train()
        self.assertTrue(result)
        self.assertTrue(clf.usable)
        self.assertFalse(clf.degenerate)

    def test_predict_returns_none_when_not_usable(self):
        clf = self._make_clf()
        label, conf = clf.predict({"power_dbm": -60, "zscore": 3.0,
                                    "snr_db": 10, "bandwidth_hz": 2e6,
                                    "duration_ms": 5, "persistence_ratio": 0.6,
                                    "freq_hz": 1575e6})
        self.assertIsNone(label)
        self.assertAlmostEqual(conf, 0.0)

    def test_predict_returns_label_when_trained(self):
        clf = self._make_clf()
        rows = self._fake_db_rows({
            "GPS_JAM": 120, "FAKE_BTS": 120, "CELL_JAM": 80
        })
        with mock.patch.object(sdr, "db_fetch_labeled_events", return_value=rows):
            with mock.patch.object(clf, "_save"):
                clf.train()

        # Không được skipTest ở đây: đó là test duy nhất của đường predict dương tính, một
        # lần train hỏng phải làm test FAIL chứ không phải biến mất khỏi báo cáo.
        self.assertTrue(clf.usable, "train() tren du lieu tach duoc ma van khong usable")

        # Một điểm nằm đúng chữ ký GPS_JAM phải được nhận ra là GPS_JAM.
        label, conf = clf.predict({"power_dbm": -30, "zscore": 8.0,
                                    "snr_db": 25, "bandwidth_hz": 2e6,
                                    "duration_ms": 5, "persistence_ratio": 1.0,
                                    "freq_hz": 1575e6})
        self.assertEqual(label, "GPS_JAM")
        self.assertIn(label, clf.classes_)
        self.assertGreater(conf, 0.5)
        self.assertLessEqual(conf, 1.0)

    def test_degenerate_model_not_usable(self):
        """Model bị mark degenerate → usable=False → predict trả None."""
        clf = self._make_clf()
        rows = self._fake_db_rows({
            "GPS_JAM": 120, "FAKE_BTS": 120, "CELL_JAM": 80
        })
        with mock.patch.object(sdr, "db_fetch_labeled_events", return_value=rows):
            with mock.patch.object(clf, "_save"):
                clf.train()

        # Force degenerate
        clf.degenerate = True
        clf.usable = False

        label, conf = clf.predict({"power_dbm": -50, "zscore": 5.0,
                                    "snr_db": 20, "bandwidth_hz": 2e6,
                                    "duration_ms": 5, "persistence_ratio": 1.0,
                                    "freq_hz": 1575.42e6})
        self.assertIsNone(label)


# ===========================================================================
# TestDatabase — SQLite CRUD với in-memory DB
# ===========================================================================

class TestDatabase(unittest.TestCase):

    def setUp(self):
        """Mỗi test dùng in-memory DB riêng."""
        self._orig_db = sdr._db
        self._orig_db_path = sdr.DB_PATH
        sdr.DB_PATH = ":memory:"
        sdr._db = None
        sdr.init_db()

    def tearDown(self):
        sdr.close_db()
        sdr._db = self._orig_db
        sdr.DB_PATH = self._orig_db_path

    def _make_result(self) -> sdr.ThreatResult:
        anomaly = make_dummy_anomaly_result(
            channel="GPS_L1", freq_hz=1575.42e6, threat_type="GPS_JAM",
            power_dbm=-45.0, baseline_dbm=-70.0, zscore=4.2
        )
        return sdr.ThreatResult(
            channel="GPS_L1", freq_hz=1575.42e6, threat_type="GPS_JAM",
            threat_level=sdr.ThreatLevel.HIGH, anomaly=anomaly,
            indicators=["Test indicator"], action="Test action",
            timestamp="2024-01-01T00:00:00Z",
            confidence=0.8,
        )

    def test_init_db_creates_tables(self):
        conn = sdr._db
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("events", tables)
        self.assertIn("spectrum_history", tables)

    def test_insert_failure_is_reported_not_swallowed(self):
        """Ghi event hỏng (bảng biến mất) từng chỉ ra logger.debug → vô hình ở mức INFO."""
        sdr._ERR_STATE.clear()
        sdr._db.execute("DROP TABLE events")
        with capture_reports() as buf:
            eid = sdr.db_log_event(self._make_result(), persistence_ratio=0.5)
        self.assertIsNone(eid)
        self.assertIn("db_log_event INSERT", buf.getvalue())
        self.assertIn("OperationalError", buf.getvalue())

    def test_read_failures_are_reported_not_swallowed(self):
        sdr._ERR_STATE.clear()
        sdr._db.execute("DROP TABLE events")
        with capture_reports() as buf:
            stats = sdr.db_label_stats()
            recent = sdr.db_fetch_recent_events()
            summary = sdr.db_summary_stats()
            labeled = sdr.db_fetch_labeled_events()
        self.assertEqual(stats["labeled"], 0)
        self.assertEqual((recent, summary, labeled), ([], {}, []))
        for site in ("db_label_stats", "db_fetch_recent_events",
                     "db_summary_stats", "db_fetch_labeled_events"):
            self.assertIn(site, buf.getvalue())

    def test_log_event_inserts_row(self):
        res = self._make_result()
        sdr.db_log_event(res, persistence_ratio=0.6)
        rows = sdr.db_fetch_recent_events()
        self.assertEqual(len(rows), 1)

    def test_log_event_fields_correct(self):
        res = self._make_result()
        sdr.db_log_event(res, persistence_ratio=0.6)
        row = sdr.db_fetch_recent_events()[0]
        self.assertEqual(row["channel"], "GPS_L1")
        self.assertEqual(row["severity"], "HIGH")
        self.assertAlmostEqual(row["zscore"], 4.2, places=2)

    def test_fetch_recent_returns_newest_first(self):
        for i in range(3):
            res = self._make_result()
            res.anomaly = make_dummy_anomaly_result(power_dbm=float(-60 + i))
            sdr.db_log_event(res)
        rows = sdr.db_fetch_recent_events()
        ids = [r["id"] for r in rows]
        self.assertEqual(ids, sorted(ids, reverse=True))

    def test_set_confirmed_updates_row(self):
        res = self._make_result()
        sdr.db_log_event(res)
        row = sdr.db_fetch_recent_events()[0]
        sdr.db_set_confirmed(row["id"], 1)
        updated = sdr.db_fetch_recent_events()[0]
        self.assertEqual(updated["confirmed"], 1)

    def test_fetch_labeled_excludes_unlabeled(self):
        # Insert 2 rows: 1 labeled, 1 không
        res = self._make_result()
        sdr.db_log_event(res)
        sdr.db_log_event(res)
        rows = sdr.db_fetch_recent_events()
        sdr.db_set_confirmed(rows[0]["id"], 1)   # label 1 row
        labeled = sdr.db_fetch_labeled_events()
        self.assertEqual(len(labeled), 1)

    def test_label_stats_reflects_confirmed_rows(self):
        res = self._make_result()
        sdr.db_log_event(res)
        row = sdr.db_fetch_recent_events()[0]
        sdr.db_set_confirmed(row["id"], 1)
        stats = sdr.db_label_stats()
        self.assertEqual(stats["labeled"], 1)
        self.assertEqual(stats["classes"], 1)

    def test_db_none_safe(self):
        """Tất cả hàm DB phải safe khi _db=None."""
        sdr.close_db()
        sdr._db = None
        self.assertEqual(sdr.db_fetch_recent_events(), [])
        self.assertEqual(sdr.db_fetch_labeled_events(), [])
        sdr.db_log_event(self._make_result())  # không crash
        sdr.init_db()   # restore cho tearDown

    # ── NEW: db_log_event return value ─────────────────────────────────────

    def test_log_event_returns_integer_id(self):
        """db_log_event() phải trả về int ID của row vừa insert."""
        res = self._make_result()
        eid = sdr.db_log_event(res)
        self.assertIsNotNone(eid)
        self.assertIsInstance(eid, int)
        self.assertGreater(eid, 0)

    def test_log_event_returns_none_when_db_none(self):
        """Trả None (không crash) khi _db=None."""
        sdr.close_db()
        sdr._db = None
        result = sdr.db_log_event(self._make_result())
        self.assertIsNone(result)
        sdr.init_db()

    def test_log_event_ids_increment(self):
        """Mỗi insert trả ID tăng dần."""
        res = self._make_result()
        id1 = sdr.db_log_event(res)
        id2 = sdr.db_log_event(res)
        self.assertGreater(id2, id1)

    # ── NEW: _auto_label — FP cases ────────────────────────────────────────

    def test_auto_label_low_threat_is_fp(self):
        """LOW threat luôn được label là FP."""
        res = self._make_result()
        res.threat_level = sdr.ThreatLevel.LOW
        eid = sdr.db_log_event(res)
        sdr._auto_label(eid, res, 0)
        row = sdr.db_fetch_recent_events()[0]
        self.assertEqual(row["confirmed"], 0)

    def test_auto_label_medium_no_consensus_not_persistent_is_fp(self):
        """MEDIUM + no dual-AI + not persistent → FP."""
        res = self._make_result()
        res.threat_level            = sdr.ThreatLevel.MEDIUM
        res.anomaly.hybrid_ai_alert = False
        res.anomaly.type_ai_alert   = False
        eid = sdr.db_log_event(res)
        sdr._auto_label(eid, res, persist_count=0)
        row = sdr.db_fetch_recent_events()[0]
        self.assertEqual(row["confirmed"], 0)

    def test_auto_label_medium_one_ai_not_persistent_is_fp(self):
        """MEDIUM + chỉ 1 AI alert + không persistent → FP."""
        res = self._make_result()
        res.threat_level            = sdr.ThreatLevel.MEDIUM
        res.anomaly.hybrid_ai_alert = True
        res.anomaly.type_ai_alert   = False
        eid = sdr.db_log_event(res)
        sdr._auto_label(eid, res, persist_count=1)
        row = sdr.db_fetch_recent_events()[0]
        self.assertEqual(row["confirmed"], 0)

    # ── NEW: _auto_label — TP cases ────────────────────────────────────────

    def test_auto_label_high_all_conditions_is_tp(self):
        """HIGH + dual-AI + persistent + |Z| > 4 → TP."""
        res = self._make_result()
        res.threat_level             = sdr.ThreatLevel.HIGH
        res.anomaly.hybrid_ai_alert  = True
        res.anomaly.type_ai_alert    = True
        res.anomaly.zscore           = 5.0
        eid = sdr.db_log_event(res)
        sdr._auto_label(eid, res, persist_count=sdr.PERSISTENCE_MIN_COUNT)
        row = sdr.db_fetch_recent_events()[0]
        self.assertEqual(row["confirmed"], 1)

    def test_auto_label_critical_all_conditions_is_tp(self):
        """CRITICAL + dual-AI + persistent + |Z| > 4 → TP."""
        res = self._make_result()
        res.threat_level             = sdr.ThreatLevel.CRITICAL
        res.anomaly.hybrid_ai_alert  = True
        res.anomaly.type_ai_alert    = True
        res.anomaly.zscore           = 6.0
        eid = sdr.db_log_event(res)
        sdr._auto_label(eid, res, persist_count=sdr.PERSISTENCE_MIN_COUNT)
        row = sdr.db_fetch_recent_events()[0]
        self.assertEqual(row["confirmed"], 1)

    # ── NEW: _auto_label — boundary / ambiguous ────────────────────────────

    def test_auto_label_high_no_dual_ai_not_labeled(self):
        """HIGH nhưng chỉ 1 AI → không đủ điều kiện TP, không label."""
        res = self._make_result()
        res.threat_level             = sdr.ThreatLevel.HIGH
        res.anomaly.hybrid_ai_alert  = True
        res.anomaly.type_ai_alert    = False
        res.anomaly.zscore           = 5.0
        eid = sdr.db_log_event(res)
        sdr._auto_label(eid, res, persist_count=sdr.PERSISTENCE_MIN_COUNT)
        row = sdr.db_fetch_recent_events()[0]
        self.assertIsNone(row["confirmed"])

    def test_auto_label_high_low_zscore_not_labeled(self):
        """|Z| < 4.0 → không đủ điều kiện TP, không label."""
        res = self._make_result()
        res.threat_level             = sdr.ThreatLevel.HIGH
        res.anomaly.hybrid_ai_alert  = True
        res.anomaly.type_ai_alert    = True
        res.anomaly.zscore           = 2.0
        eid = sdr.db_log_event(res)
        sdr._auto_label(eid, res, persist_count=sdr.PERSISTENCE_MIN_COUNT)
        row = sdr.db_fetch_recent_events()[0]
        self.assertIsNone(row["confirmed"])

    def test_auto_label_medium_with_consensus_not_labeled(self):
        """MEDIUM + dual-AI agree → gray zone, không label."""
        res = self._make_result()
        res.threat_level             = sdr.ThreatLevel.MEDIUM
        res.anomaly.hybrid_ai_alert  = True
        res.anomaly.type_ai_alert    = True
        eid = sdr.db_log_event(res)
        sdr._auto_label(eid, res, persist_count=sdr.PERSISTENCE_MIN_COUNT)
        row = sdr.db_fetch_recent_events()[0]
        self.assertIsNone(row["confirmed"])

    # ── NEW: _auto_label — safety ──────────────────────────────────────────

    def test_auto_label_none_event_id_safe(self):
        """event_id=None không crash."""
        res = self._make_result()
        res.threat_level = sdr.ThreatLevel.LOW
        sdr._auto_label(None, res, 0)

    def test_auto_label_db_none_safe(self):
        """_db=None không crash."""
        sdr.close_db()
        sdr._db = None
        res = self._make_result()
        res.threat_level = sdr.ThreatLevel.LOW
        sdr._auto_label(1, res, 0)
        sdr.init_db()


# ===========================================================================
# TestDowngradeHelper
# ===========================================================================

class TestDowngradeHelper(unittest.TestCase):

    def test_downgrade_critical_to_high(self):
        self.assertEqual(sdr._downgrade_one("CRITICAL"), "HIGH")

    def test_downgrade_high_to_medium(self):
        self.assertEqual(sdr._downgrade_one("HIGH"), "MEDIUM")

    def test_downgrade_medium_to_low(self):
        self.assertEqual(sdr._downgrade_one("MEDIUM"), "LOW")

    def test_downgrade_low_to_ok(self):
        self.assertEqual(sdr._downgrade_one("LOW"), "OK")

    def test_downgrade_ok_stays_ok(self):
        self.assertEqual(sdr._downgrade_one("OK"), "OK")

    def test_downgrade_unknown_returns_input_and_reports(self):
        sdr._ERR_STATE.clear()
        with capture_reports() as buf:
            self.assertEqual(sdr._downgrade_one("BOGUS"), "BOGUS")
        self.assertIn("_downgrade_one", buf.getvalue())
        self.assertIn("BOGUS", buf.getvalue())

    def test_downgrade_accepts_threatlevel_enum(self):
        """Regression: nơi gọi duy nhất trong production truyền ThreatLevel, không phải chuỗi.

        str(ThreatLevel.HIGH).upper() = 'THREATLEVEL.HIGH' không nằm trên thang → ValueError bị
        nuốt → Gate [4] không bao giờ hạ được cấp nào.  Test cũ chỉ dùng chuỗi nên không thấy.
        """
        T = sdr.ThreatLevel
        self.assertIs(sdr._downgrade_one(T.CRITICAL), T.HIGH)
        self.assertIs(sdr._downgrade_one(T.HIGH), T.MEDIUM)
        self.assertIs(sdr._downgrade_one(T.MEDIUM), T.LOW)
        self.assertIs(sdr._downgrade_one(T.LOW), T.OK)
        self.assertIs(sdr._downgrade_one(T.OK), T.OK)

    def test_downgrade_case_insensitive(self):
        self.assertEqual(sdr._downgrade_one("critical"), "HIGH")


# ===========================================================================
# TestEWAnomalyResultProperties
# ===========================================================================

class TestEWAnomalyResultProperties(unittest.TestCase):

    def test_ai_alert_true_if_hybrid_alert(self):
        r = make_dummy_anomaly_result(hybrid_ai_alert=True)
        self.assertTrue(r.ai_alert)

    def test_ai_alert_true_if_type_alert(self):
        r = make_dummy_anomaly_result(type_ai_alert=True)
        self.assertTrue(r.ai_alert)

    def test_ai_alert_false_if_neither(self):
        r = make_dummy_anomaly_result()
        self.assertFalse(r.ai_alert)

    def test_ai_both_agree_requires_both(self):
        r = make_dummy_anomaly_result(hybrid_ai_alert=True, type_ai_alert=True)
        self.assertTrue(r.ai_both_agree)

    def test_ai_both_agree_false_one_only(self):
        r = make_dummy_anomaly_result(hybrid_ai_alert=True, type_ai_alert=False)
        self.assertFalse(r.ai_both_agree)

    def test_any_alert_power(self):
        r = make_dummy_anomaly_result(power_alert=True)
        self.assertTrue(r.any_alert)

    def test_any_alert_entropy(self):
        r = make_dummy_anomaly_result(entropy_alert=True)
        self.assertTrue(r.any_alert)

    def test_any_alert_burst(self):
        r = make_dummy_anomaly_result(burst_alert=True)
        self.assertTrue(r.any_alert)

    def test_any_alert_structural(self):
        r = make_dummy_anomaly_result(structural_alert=True)
        self.assertTrue(r.any_alert)

    def test_any_alert_swept(self):
        r = make_dummy_anomaly_result(swept_alert=True)
        self.assertTrue(r.any_alert)

    def test_any_alert_false_when_all_clear(self):
        r = make_dummy_anomaly_result()
        self.assertFalse(r.any_alert)


# ===========================================================================
# TestWatchlist — sanity check danh sách kênh quan sát
# ===========================================================================

class TestWatchlist(unittest.TestCase):

    def test_watchlist_not_empty(self):
        self.assertGreater(len(sdr.WATCHLIST), 0)

    def test_all_channels_have_name(self):
        for ch in sdr.WATCHLIST:
            self.assertTrue(len(ch.name) > 0)

    def test_all_channels_have_positive_freq(self):
        for ch in sdr.WATCHLIST:
            self.assertGreater(ch.freq_hz, 0)

    def test_gps_l1_present(self):
        names = {ch.name for ch in sdr.WATCHLIST}
        self.assertIn("GPS_L1", names)

    def test_all_priorities_are_1_2_or_3(self):
        for ch in sdr.WATCHLIST:
            self.assertIn(ch.priority, (1, 2, 3))

    def test_no_duplicate_names(self):
        names = [ch.name for ch in sdr.WATCHLIST]
        self.assertEqual(len(names), len(set(names)))


# ===========================================================================
# "KHÔNG NUỐT LỖI" — helpers
# ===========================================================================

@contextlib.contextmanager
def capture_reports():
    """Ép report_error đi đường stderr (giả lập chưa có handler nào) và bắt lại những gì nó in."""
    buf = io.StringIO()
    lg = logging.getLogger("rf_sentinel")
    with mock.patch.object(lg, "handlers", []), contextlib.redirect_stderr(buf):
        yield buf


def _load_copy(filename: str, modname: str):
    """Nạp một bản riêng của module anh em (không đụng vào bản main đang dùng)."""
    spec = _ilu.spec_from_file_location(modname, os.path.join(_SRC, filename))
    mod = _ilu.module_from_spec(spec)
    sys.modules[modname] = mod
    try:
        spec.loader.exec_module(mod)
    except BaseException:
        sys.modules.pop(modname, None)
        raise
    return mod


def _raised(exc):
    """Trả về exception đã thật sự bị raise (có __traceback__ để lấy file:dòng)."""
    try:
        raise exc
    except Exception as e:
        return e


# ===========================================================================
# TestReportError — hợp đồng của report_error()
# ===========================================================================

class TestReportError(unittest.TestCase):

    def setUp(self):
        sdr._ERR_STATE.clear()

    def test_first_occurrence_prints_type_message_and_location(self):
        with capture_reports() as buf:
            sdr.report_error("site-a", _raised(ValueError("boom")))
        out = buf.getvalue()
        self.assertIn("[ERR] site-a: ValueError: boom", out)
        self.assertIn("test_sdr_sentinel.py:", out)          # file:dòng nơi lỗi được raise

    def test_warning_level_uses_warn_tag(self):
        with capture_reports() as buf:
            sdr.report_error("site-w", ValueError("x"), level="warning")
        self.assertIn("[WARN] site-w", buf.getvalue())

    def test_plain_string_message(self):
        with capture_reports() as buf:
            sdr.report_error("site-s", "hello world")
        self.assertIn("[ERR] site-s: hello world", buf.getvalue())

    def test_repeats_are_folded_and_counted_never_dropped(self):
        with mock.patch.object(sdr.time, "monotonic", side_effect=[0.0, 1.0, 2.0, 31.0]):
            with capture_reports() as buf:
                for _ in range(4):
                    sdr.report_error("hot", ValueError("x"), every=30)
        out = buf.getvalue()
        self.assertEqual(out.count("[ERR] hot"), 2)          # lần 1 và lần sau cửa sổ 30 s
        self.assertIn("+2 lan lap lai bi gop", out)          # 2 lần ở giữa được ĐẾM, không mất

    def test_every_none_prints_only_first_ever(self):
        with capture_reports() as buf:
            for _ in range(5):
                sdr.report_error("once", ValueError("x"), every=None)
        self.assertEqual(buf.getvalue().count("[ERR] once"), 1)

    def test_every_zero_prints_every_time(self):
        with capture_reports() as buf:
            for _ in range(3):
                sdr.report_error("always", ValueError("x"), every=0)
        self.assertEqual(buf.getvalue().count("[ERR] always"), 3)

    def test_distinct_sites_do_not_suppress_each_other(self):
        with capture_reports() as buf:
            sdr.report_error("site-1", ValueError("x"), every=None)
            sdr.report_error("site-2", ValueError("x"), every=None)
        self.assertIn("site-1", buf.getvalue())
        self.assertIn("site-2", buf.getvalue())

    def test_goes_through_logger_when_configured(self):
        with self.assertLogs("rf_sentinel", level="WARNING") as cm:
            sdr.report_error("via-logger", ValueError("b"), every=0)
        self.assertTrue(any("[ERR] via-logger" in line for line in cm.output))

    def test_logger_failure_falls_back_to_stderr(self):
        lg = logging.getLogger("rf_sentinel")
        buf = io.StringIO()
        with mock.patch.object(lg, "handlers", [logging.NullHandler()]), \
                mock.patch.object(lg, "log", side_effect=RuntimeError("disk full")), \
                contextlib.redirect_stderr(buf):
            sdr.report_error("z", ValueError("b"), every=0)
        out = buf.getvalue()
        self.assertIn("logger hong", out)
        self.assertIn("[ERR] z: ValueError: b", out)         # thông điệp gốc vẫn tới tay người dùng

    def test_helper_copies_are_identical_across_modules(self):
        agents = sdr._rf_agents_mod
        self.assertIsNotNone(agents, "rf_sentinel_agents.py khong nap duoc")
        ui = _load_copy("rf_sentinel_ui.py", "rf_sentinel_ui_copycheck")
        ref = inspect.getsource(sdr.report_error)
        self.assertEqual(ref, inspect.getsource(agents.report_error))
        self.assertEqual(ref, inspect.getsource(ui.report_error))


# ===========================================================================
# TestNoSilentFailures — các chỗ trước đây nuốt lỗi giờ phải lên tiếng
# ===========================================================================

class TestNoSilentFailures(unittest.TestCase):

    def setUp(self):
        sdr._ERR_STATE.clear()

    def test_missing_optional_dependency_is_reported_once(self):
        with capture_reports() as buf:
            r1 = sdr._dyn_import("definitely_not_a_real_package_xyz")
            r2 = sdr._dyn_import("definitely_not_a_real_package_xyz")
        self.assertIsNone(r1)
        self.assertIsNone(r2)
        self.assertEqual(buf.getvalue().count("DEP definitely_not_a_real_package_xyz"), 1)

    def test_missing_attribute_is_reported(self):
        with capture_reports() as buf:
            self.assertIsNone(sdr._dyn_import("os", "no_such_attr"))
        self.assertIn("DEP os.no_such_attr", buf.getvalue())

    def test_sibling_module_syntax_error_is_reported_once_and_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "rf_zz_broken.py"), "w", encoding="utf-8") as fh:
                fh.write("x = 1\ndef broken(:\n")
            pats = ["rf_zz_broken.py", "rf_zz_broken*.py"]
            with mock.patch.object(sdr, "_THIS_DIR", d), \
                    mock.patch.object(sdr, "_SIBLING_LOAD_FAILED", set()), \
                    capture_reports() as buf:
                results = [sdr._load_sibling_module("rf_zz_broken", pats) for _ in range(5)]
        out = buf.getvalue()
        self.assertTrue(all(r is None for r in results))
        self.assertEqual(out.count("LOAD rf_zz_broken"), 1)   # 5 lần gọi, 1 lần báo
        self.assertIn("SyntaxError", out)
        self.assertIn("line 2", out)
        self.assertNotIn("rf_zz_broken", sys.modules)         # không để module nửa vời lại

    def test_sibling_module_is_loaded_once_and_keeps_its_state(self):
        """Bản cũ exec lại file trên MỖI event → _sse_clients bị reset, SSE live không tới browser."""
        pats = ["rf_sentinel_ui.py", "rf_sentinel_ui*.py"]
        a = sdr._load_sibling_module("rf_sentinel_ui", pats)
        self.assertIsNotNone(a)
        a._sse_clients.append("MARK")
        try:
            for _ in range(20):
                b = sdr._load_sibling_module("rf_sentinel_ui", pats)
            self.assertIs(a, b)
            self.assertIn("MARK", b._sse_clients)
        finally:
            a._sse_clients.remove("MARK")

    def test_no_module_left_registered_after_failed_load(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "rf_zz_bad2.py"), "w", encoding="utf-8") as fh:
                fh.write("raise RuntimeError('import-time failure')\n")
            with mock.patch.object(sdr, "_THIS_DIR", d), \
                    mock.patch.object(sdr, "_SIBLING_LOAD_FAILED", set()), \
                    capture_reports() as buf:
                self.assertIsNone(sdr._load_sibling_module("rf_zz_bad2", ["rf_zz_bad2.py"]))
        self.assertIn("RuntimeError: import-time failure", buf.getvalue())
        self.assertNotIn("rf_zz_bad2", sys.modules)


# ===========================================================================
# TestRFGateDowngrades — Gate [4] phải HẠ cấp thật (bug bị che bởi ValueError nuốt)
# ===========================================================================

class TestRFGateDowngrades(unittest.TestCase):

    class _FakeRF:
        usable = True

        def __init__(self, label):
            self._label = label

        def predict(self, feat):
            return self._label, 0.99

    def _result(self, level):
        anomaly = make_dummy_anomaly_result(threat_type="GPS_JAM", zscore=9.0)
        return sdr.ThreatResult(
            channel="GPS_L1", freq_hz=1575.42e6, threat_type="GPS_JAM",
            threat_level=level, anomaly=anomaly, indicators=[], action="",
            timestamp="2024-01-01T00:00:00Z", confidence=0.9)

    def test_rf_disagreement_lowers_level_by_exactly_one_rung(self):
        with mock.patch.object(sdr, "_get_rf", return_value=self._FakeRF("FAKE_BTS")):
            res = sdr.apply_confidence_gate(self._result(sdr.ThreatLevel.HIGH), True, 5)
        self.assertIs(res.threat_level, sdr.ThreatLevel.MEDIUM)
        self.assertTrue(any("RF-DISAGREE" in i for i in res.indicators))

    def test_rf_agreement_keeps_level(self):
        with mock.patch.object(sdr, "_get_rf", return_value=self._FakeRF("GPS_JAM")):
            res = sdr.apply_confidence_gate(self._result(sdr.ThreatLevel.HIGH), True, 5)
        self.assertIs(res.threat_level, sdr.ThreatLevel.HIGH)

    def test_rf_never_raises_a_level(self):
        with mock.patch.object(sdr, "_get_rf", return_value=self._FakeRF("FAKE_BTS")):
            res = sdr.apply_confidence_gate(self._result(sdr.ThreatLevel.OK), True, 5)
        self.assertIs(res.threat_level, sdr.ThreatLevel.OK)


# ===========================================================================
# TestSDRFailuresAreLoud — radio chết KHÔNG được trông giống 'không có tín hiệu'
# ===========================================================================

class TestSDRFailuresAreLoud(unittest.TestCase):

    class _DeadSDR:
        def _die(self, *a, **k):
            raise RuntimeError("usb unplugged")
        start_rx = read_samples = set_center_freq = stop_rx = _die

    def setUp(self):
        sdr._ERR_STATE.clear()

    def test_dead_radio_is_reported_at_every_call_site(self):
        eng = sdr.FastSweepEngine(self._DeadSDR())
        eng.streaming = True
        with mock.patch.object(sdr, "SWEEP_DWELL_S", 0), \
                mock.patch.object(sdr, "SWEEP_SETTLE_S", 0), \
                capture_reports() as buf:
            self.assertFalse(eng.tune(433e6))
            iq = eng.snapshot()
            eng.stop_stream()
        out = buf.getvalue()
        self.assertEqual(len(iq), 0)
        for site in ("SDR set_center_freq", "SDR start_rx", "SDR read_samples", "SDR stop_rx"):
            self.assertIn(site, out)
        self.assertIn("usb unplugged", out)

    def test_ai_predict_failure_is_reported(self):
        ai = sdr.HybridCognitiveAI()
        ai.trained = True                       # ép vào nhánh có try/except
        with capture_reports() as buf:
            score, label = ai.predict(object())  # object() không có feature → _vec() nổ
        self.assertEqual((score, label), (0.0, "ERROR"))
        self.assertIn("HybridCognitiveAI.predict", buf.getvalue())


# ===========================================================================
# TestMainSurfacesWorkerFailure — lỗi trong thread quét phải nổi lên, exit code != 0
# ===========================================================================

class TestMainSurfacesWorkerFailure(unittest.TestCase):

    _STUBS = ("print_banner", "init_db", "init_rf", "init_agents", "start_web_ui",
              "start_spectrum_gui", "verify_rx_guard_integrity", "connect_hackrf",
              "init_baseline", "close_db", "HybridCognitiveAI", "RFAnomalyAI")

    def _run_main(self, monitor):
        stubs = {name: mock.DEFAULT for name in self._STUBS}
        with mock.patch.multiple(sdr, **stubs), \
                mock.patch.object(sdr, "monitor_loop", monitor), \
                self.assertLogs("rf_sentinel", level="INFO") as cm:
            rc = sdr.main(["--run"])
        return rc, "\n".join(cm.output)

    def test_worker_exception_is_logged_with_traceback_and_exit_code_is_1(self):
        def dying_worker(*a, **k):
            raise RuntimeError("sweep thread died")
        rc, out = self._run_main(dying_worker)
        self.assertEqual(rc, 1)
        self.assertIn("sweep thread died", out)
        self.assertIn("Traceback", out)

    def test_clean_worker_exit_returns_zero(self):
        rc, out = self._run_main(lambda *a, **k: None)
        self.assertEqual(rc, 0)
        self.assertNotIn("Traceback", out)


# ===========================================================================
# TestAgentsNoSilentFailure
# ===========================================================================

class TestAgentsNoSilentFailure(unittest.TestCase):

    def setUp(self):
        self.ag = sdr._rf_agents_mod
        self.assertIsNotNone(self.ag, "rf_sentinel_agents.py khong nap duoc")
        self.ag._ERR_STATE.clear()

    def test_corrupt_queue_is_reported_and_original_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            al_dir = os.path.join(d, "active_learning")
            os.makedirs(al_dir)
            with open(os.path.join(al_dir, "queue.json"), "w", encoding="utf-8") as fh:
                fh.write("{not json")
            with capture_reports() as buf:
                agent = self.ag.ActiveLearningAgent(base_dir=d)
            self.assertEqual(agent._queue, [])
            self.assertIn("ActiveLearningAgent._load queue.json", buf.getvalue())
            backups = [f for f in os.listdir(al_dir) if f.startswith("queue.json.corrupt-")]
            self.assertEqual(len(backups), 1)
            with open(os.path.join(al_dir, backups[0]), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "{not json")     # dữ liệu gốc không mất

    def test_missing_queue_on_first_run_is_normal_and_silent(self):
        with tempfile.TemporaryDirectory() as d:
            with capture_reports() as buf:
                agent = self.ag.ActiveLearningAgent(base_dir=d)
        self.assertEqual(agent._queue, [])
        self.assertEqual(buf.getvalue(), "")

    def test_emit_without_logger_prints_warning_but_not_info(self):
        with capture_reports() as buf:
            self.ag._emit(None, "TAG", "chi la thong tin", "info")
            self.ag._emit(None, "TAG", "canh bao that", "warning")
        self.assertNotIn("chi la thong tin", buf.getvalue())
        self.assertIn("[TAG] canh bao that", buf.getvalue())

    def test_safe_float_reports_bad_value_but_not_none(self):
        with capture_reports() as buf:
            self.assertEqual(self.ag._safe_float(None, 7.0), 7.0)
        self.assertEqual(buf.getvalue(), "")                 # 'không có giá trị' là bình thường
        with capture_reports() as buf:
            self.assertEqual(self.ag._safe_float("abc", 7.0), 7.0)
        self.assertIn("_safe_float", buf.getvalue())
        self.assertIn("abc", buf.getvalue())

    def _decoder_with_fake_rtl433(self, tmpdir, completed):
        import subprocess
        dec = self.ag.ProtocolDecoderAgent(base_dir=tmpdir)
        dec._rtl_433_path = "/fake/rtl_433"
        iq = np.zeros(64, dtype=np.complex64)
        with mock.patch.object(self.ag.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], **completed)):
            with capture_reports() as buf:
                result = dec._decode_via_rtl433(iq, 250000, 433.92e6)
        return result, buf.getvalue(), dec

    def test_rtl433_nonzero_exit_is_reported_not_treated_as_no_packets(self):
        with tempfile.TemporaryDirectory() as d:
            result, out, dec = self._decoder_with_fake_rtl433(
                d, dict(returncode=2, stdout="", stderr="usb_claim_interface error -6"))
            leftovers = [f for f in os.listdir(dec.dir) if f.startswith("_tmp_")]
        self.assertIsNone(result)
        self.assertIn("rtl_433 exit code", out)
        self.assertIn("usb_claim_interface", out)          # stderr của rtl_433 tới tay người dùng
        self.assertEqual(leftovers, [])                     # file tạm vẫn được dọn

    def test_rtl433_clean_exit_with_no_packets_is_normal_and_silent(self):
        with tempfile.TemporaryDirectory() as d:
            result, out, _ = self._decoder_with_fake_rtl433(
                d, dict(returncode=0, stdout="", stderr=""))
        self.assertIsNone(result)
        self.assertEqual(out, "")

    def test_child_script_failure_is_captured_and_reported(self):
        """Trước đây stdout/stderr của script con bị ném vào DEVNULL: crash không để lại dấu vết."""
        code = "import sys; print('hello-out'); print('hello-err', file=sys.stderr); sys.exit(3)"
        with tempfile.TemporaryDirectory() as d:
            log = os.path.join(d, "child.log")
            with capture_reports() as buf:
                p = self.ag._spawn_logged([sys.executable, "-c", code], log, "unit-test script")
                p.wait(timeout=30)
                deadline = time.time() + 15
                while "exit=3" not in buf.getvalue() and time.time() < deadline:
                    time.sleep(0.05)
            self.assertIn("unit-test script exit=3", buf.getvalue())
            with open(log, encoding="utf-8") as fh:
                text = fh.read()
        self.assertIn("hello-out", text)
        self.assertIn("hello-err", text)


# ===========================================================================
# TestUIFailuresAreLoud
# ===========================================================================

class TestUIFailuresAreLoud(unittest.TestCase):

    def setUp(self):
        self.ui = _load_copy("rf_sentinel_ui.py", "rf_sentinel_ui_under_test")
        self.ui._ERR_STATE.clear()

    def test_sse_fanout_overflow_is_reported(self):
        tiny = queue.Queue(maxsize=1)
        tiny.put("full")
        with mock.patch.object(self.ui, "_fan_out_queue", tiny), \
                mock.patch.object(self.ui, "_ensure_broadcaster"), \
                capture_reports() as buf:
            self.ui.broadcast_sse({"type": "event"})
        self.assertIn("SSE fan-out queue full", buf.getvalue())

    def test_slow_sse_client_is_disconnected_and_reported(self):
        slow = queue.Queue(maxsize=1)
        slow.put("x")                                        # đầy sẵn → put_nowait sẽ Full
        self.ui._sse_clients.append(slow)
        fan = queue.Queue()
        fan.put("data: 1\n\n")
        fan.put(None)                                        # poison pill → vòng lặp thoát
        with mock.patch.object(self.ui, "_fan_out_queue", fan), capture_reports() as buf:
            self.ui._broadcaster_loop()
        self.assertNotIn(slow, self.ui._sse_clients)
        self.assertIn("SSE client too slow", buf.getvalue())

    def test_missing_flask_is_reported_not_silently_skipped(self):
        with mock.patch.dict(sys.modules, {"flask": None}), capture_reports() as buf:
            noop = lambda *a, **k: None
            self.ui.register(mock.MagicMock(), noop, noop, noop, noop, noop, noop, noop,
                             [], [], [False])
        self.assertIn("rf_sentinel_ui.register", buf.getvalue())


# ===========================================================================
# TestNoSilentExcept — luật 'không nuốt lỗi' được thực thi bằng AST (tools/check_no_swallow.py)
# ===========================================================================

def _load_checker():
    # Tìm check_no_swallow.py theo nhiều vị trí để hoạt động ở cả layout
    # repo chuẩn lẫn layout phẳng (tất cả file cùng thư mục):
    #   1. _SRC/../tools/   — repo chuẩn: SDR-BLUE-TEAM.py trong real_warfare/
    #   2. _SRC/tools/      — tools/ cạnh file chính
    #   3. _THIS_TEST_DIR/tools/ — tools/ cạnh file test
    #   4. _SRC/            — layout phẳng, checker cùng thư mục với file chính
    #   5. _THIS_TEST_DIR/  — layout phẳng, checker cùng thư mục với file test
    _fname = "check_no_swallow.py"
    candidates = [
        os.path.join(_SRC,           "..", "tools", _fname),
        os.path.join(_SRC,           "tools",       _fname),
        os.path.join(_THIS_TEST_DIR, "tools",       _fname),
        os.path.join(_SRC,                          _fname),
        os.path.join(_THIS_TEST_DIR,                _fname),
    ]
    path = next((os.path.abspath(c) for c in candidates if os.path.isfile(c)), None)
    if path is None:
        searched = "\n  ".join(os.path.abspath(c) for c in candidates)
        # Cố ý FAIL to, không skip: một guard biến mất trong im lặng là chính thứ ta đang cấm.
        raise FileNotFoundError(
            f"khong thay tools/check_no_swallow.py. Da tim:\n  {searched}"
        )
    spec = _ilu.spec_from_file_location("check_no_swallow", path)
    mod = _ilu.module_from_spec(spec)
    sys.modules["check_no_swallow"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestNoSilentExcept(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.chk = _load_checker()

    def test_repo_has_no_swallowed_exceptions(self):
        root = os.path.abspath(os.path.join(_SRC, ".."))
        problems = []
        targets = self.chk.default_targets()
        self.assertGreaterEqual(len(targets), 5, "checker khong tim thay file nao de quet")
        for f in targets:
            for lineno, kind, what in self.chk.find_violations(f):
                problems.append(f"{os.path.relpath(str(f), root)}:{lineno}: [{kind}] {what}")
        self.assertEqual(problems, [], "Cho nuot loi:\n  " + "\n  ".join(problems))

    _BAD = '''
import queue, contextlib, logging
logger = logging.getLogger("x")

def silent():
    try: 1/0
    except Exception: pass

def fallback_return():
    try: 1/0
    except Exception: return None

def fallback_value():
    try: v = int("x")
    except ValueError: v = 0
    return v

def debug_only():
    try: 1/0
    except Exception as e: logger.debug(f"boom {e}")

def leveled_debug(self):
    try: 1/0
    except Exception as e: self._log(f"boom {e}", "debug")

def bare():
    try: 1/0
    except: print("x")

def suppressed():
    with contextlib.suppress(Exception):
        1/0

def marker_wrong_type():
    try: 1/0
    except ZeroDivisionError:  # expected-exception: totally fine i promise
        pass

def marker_no_reason():
    q = queue.Queue()
    try: q.get_nowait()
    except queue.Empty:  # expected-exception: x
        pass
'''

    _GOOD = '''
import queue

def ok_marker():
    q = queue.Queue()
    try: q.get_nowait()
    except queue.Empty:  # expected-exception: idle poll, empty most of the time
        pass

def ok_reraise():
    try: 1/0
    except Exception: raise

def ok_prints():
    try: 1/0
    except Exception as e: print("bad", e)

def ok_leveled_warning(self):
    try: 1/0
    except Exception as e: self._log(f"boom {e}", "warning")

def ok_report_error():
    try: 1/0
    except Exception as e: report_error("x", e)
'''

    def _scan(self, source):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "sample.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(source)
            return self.chk.find_violations(path)

    def test_checker_flags_every_violation_kind(self):
        kinds = sorted(k for _, k, _ in self._scan(self._BAD))
        self.assertEqual(kinds, sorted([
            "SILENT", "SILENT", "FALLBACK-NO-REPORT", "DEBUG-ONLY", "DEBUG-ONLY",
            "BARE-EXCEPT", "SUPPRESS", "SILENT", "SILENT"]))

    # Assembled at runtime so THIS file never contains the empty-catch pattern itself
    # (the checker scans the test file too).
    _EMPTY = "{" + "}"

    def test_checker_flags_javascript_catch_blocks_that_never_report(self):
        silent_flag = "{ flag = false; }"
        js = ('_PAGE = """<script>\n'
              'try { go(); } catch(_) ' + self._EMPTY + '\n'                # 2 rỗng
              'try { go(); } catch ' + self._EMPTY + '\n'                   # 3 rỗng, không binding
              'p.catch(() => ' + self._EMPTY + ');\n'                       # 4 promise rỗng
              'try { go(); } catch(e) ' + silent_flag + '\n'                # 5 KHÔNG rỗng nhưng câm
              'try { go(); } catch(e) { console.error(e); }\n'              # 6 ok
              'p.catch(e => reportUiError("x", e));\n'                      # 7 ok
              'try { go(); } catch(e) { reportUiError("x", e); ui.bad(); }\n'  # 8 ok
              'try { go(); } catch(e) { if (x) { y(); } throw e; }\n'       # 9 ok, có brace lồng
              '</script>"""\n')
        found = self._scan(js)
        self.assertEqual([k for _, k, _ in found], ["JS-SWALLOW"] * 4)
        self.assertEqual([ln for ln, _, _ in found], [2, 3, 4, 5])          # đúng số dòng

    def test_checker_gives_same_verdicts_without_ast_unparse(self):
        """ast.unparse only exists on Python >= 3.9; the checker must still work on 3.8."""
        def verdicts():
            # Với dòng `except`, so cả chữ hiển thị (queue.Empty ≠ Empty), không chỉ kết luận:
            # 'Empty' nằm trong EXPECTED_TYPES nên nếu chỉ so kết luận thì fallback hỏng cũng lọt.
            return [(ln, k, what if what.startswith("except") else "") for ln, k, what in self._scan(self._BAD)]
        expected = verdicts()
        self.assertIn("except queue.Empty", [w for _, _, w in expected])   # sanity: mẫu có ca Attribute
        with mock.patch.object(self.chk, "_HAS_UNPARSE", False):
            self.assertEqual(verdicts(), expected)
            self.assertEqual(self._scan(self._GOOD), [])         # marker 'queue.Empty' vẫn nhận ra

    def test_checker_accepts_legitimate_forms(self):
        self.assertEqual(self._scan(self._GOOD), [])

    def test_checker_does_not_skip_unparsable_files(self):
        with self.assertRaises(SyntaxError):
            self._scan("def broken(:\n")


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="RF Sentinel Test Suite")
    parser.add_argument("pattern", nargs="?", default=None,
                        help="Optional test class/method filter (e.g. TestDSP)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    verbosity = 2 if args.verbose else 1

    if args.pattern:
        suite = unittest.TestLoader().loadTestsFromName(args.pattern,
                                                        module=sys.modules[__name__])
    else:
        suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
