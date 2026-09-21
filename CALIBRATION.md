# Calibration Guide — RF Sentinel

> **Important**: Without calibration, dBm values are relative only (default offset `-50.0 dB`). The system still operates and detects anomalies via Z-score (relative), but absolute dBm thresholds will be incorrect.

---

## Why Calibration Is Needed

HackRF One (like most budget SDRs) has:

- **Non-flat frequency response**: actual gain varies with frequency, especially at the edges of the passband
- **Temperature drift**: gain shifts as the device warms up
- **LNA/VGA gain accuracy**: amplifiers have an accuracy of ±3–5 dB

`CALIBRATION_BANDS` in the code divides the spectrum into 8 bands, each with its own `offset_dB`:

```
offset_dB = true_power_dBm − sdr_reading_dBm
```

---

## Equipment Options

**Option 1 (most accurate)**: Signal generator
- Any RF signal generator with a calibrated output
- 50 Ω terminator
- Attenuator (if generator output is too strong)

**Option 2 (practical)**: Known signal source
- A Wi-Fi device at a fixed transmit power (e.g., 20 dBm = 100 mW)
- Fixed measurement distance; use a path-loss model to estimate received power

**Option 3 (minimal)**: Compare against a calibrated SDR
- Use two SDRs measuring the same source and take the offset

---

## Calibration Procedure (Signal Generator)

### Step 1: Prepare

```bash
# Start in web-only mode
python SDR-BLUE-TEAM.py --web-only
# Open the UI: http://127.0.0.1:1717/
```

### Step 2: Measure Each Band

Repeat for each of the 8 frequency bands:

| Band | Recommended Test Frequency |
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
1. Set the signal generator to the test frequency with a known output level `P_gen_dBm` (e.g., −30 dBm).
2. Connect it to the HackRF via cable + appropriate attenuator.
3. Open **Channel monitor** in the UI and select a channel in that band.
4. Record `P_sdr_dBm` from the UI.
5. Compute `offset = P_gen_dBm − P_sdr_dBm`.

### Step 3: Enter Offsets

Via the UI:

```
UI → Calibration → enter per-band offsets → Save
```

Or directly via the API:

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

### Step 4: Verify

After saving, the UI displays `✅ CALIBRATION_VERIFIED` and the calibration warning banner in the log disappears.

---

## FHSS Templates for Drone Detection

> ⚠️ **The default templates are synthetic data** — not captured from real hardware. Drone recognition accuracy may be poor in your environment.

### Capturing Real Templates from DJI / ELRS

**Prerequisites**: you own the device, you are in a controlled environment, and you have the legal right to transmit on the relevant frequencies.

```bash
# 1. Place the drone ~5 m from the HackRF antenna, flat ground, no obstructions
# 2. Power on the remote controller and drone but do NOT arm the motors
# 3. Capture 30 seconds of IQ data at 2.4 GHz
hackrf_transfer -r /tmp/dji_24g_raw.iq -f 2440000000 -s 2000000 -n 60000000

# 4. Repeat at 5.8 GHz
hackrf_transfer -r /tmp/dji_58g_raw.iq -f 5800000000 -s 2000000 -n 60000000
```

Then use an analysis script to extract the centroid sequence:

```python
import numpy as np
import pickle

raw = np.fromfile('/tmp/dji_24g_raw.iq', dtype=np.complex64)
# Compute PSD over 1024-sample windows → spectral centroid → sequence
# Store in FHSS_TEMPLATES['DJI_24G'] in SDR-BLUE-TEAM.py
```

See `FHSSTracker._centroid_hist_entropy()` and `_spectral_centroid_norm()` for the expected template format.

---

## Recalibration Schedule

| Situation | Action |
|---|---|
| HackRF or antenna replaced | Full recalibration from scratch |
| Ambient temperature change > 15°C | Recalibrate |
| After 6 months of operation | Recheck 2–3 primary bands |
| Sudden drop in RF model accuracy | Check calibration before retraining |

---

## Reference Offset Values (Typical HackRF One)

The values below are indicative only. Your hardware and antenna will differ:

| Band | Typical Offset |
|---|---|
| 100–400 MHz | −2 to −5 dB |
| 400–1000 MHz | −4 to −7 dB |
| 1000–2400 MHz | −6 to −10 dB |
| 2400–6000 MHz | −8 to −15 dB |

Larger offsets at higher frequencies are normal, due to cable loss and the frequency response of the internal LNA.
