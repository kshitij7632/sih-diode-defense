# GeoGuards Machine Learning & Detection Subsystem

This document provides a comprehensive technical guide to the machine learning pipelines, feature engineering schemas, specialized detector modules, and benchmarking suites within **GeoGuards** (Smart India Hackathon 2026, Problem Statement 26145: *AI-Based Detection of Cyber Threats in Unidirectional IP Traffic*).

---

## 1. Directory Structure

```
ml/
├── artifacts/              # Preprocessed data splits (.npz, .json)
├── scripts/
│   ├── audit_datasets.py   # Dataset auditing and manifest generation
│   ├── feature_schema.py   # Canonical feature definitions (V1 & V2)
│   ├── preprocess_data.py  # Leakage-safe data parsing and scaler generation
│   └── train_models.py     # Multi-model training, calibration & evaluation
backend/
├── specialized_detectors.py# Detectors for 6 PS threat classes
├── correlation.py          # Cross-flow correlation & timeline tracker
├── streaming_engine.py     # Streaming PCAP replay engine
├── benchmark.py            # Latency and throughput benchmark suite
├── anomaly_detector.py     # Real-benign Isolation Forest
├── behaviour_analytics.py  # Statistical heuristic engine
├── risk_fusion.py          # Multi-signal risk fusion engine
├── schemas.py              # Pydantic standardized alert schemas
└── main.py                 # FastAPI application
```

---

## 2. Canonical Feature Schemas

### Baseline Feature Schema (V1 - 6 Attributes)
Lightweight representation optimized for sub-millisecond wire-speed processing:
1. `iat_mean`: Mean inter-arrival time between packets (seconds).
2. `iat_std`: Standard deviation of inter-arrival time (seconds).
3. `pkt_len_mean`: Mean packet length (bytes).
4. `pkt_len_std`: Standard deviation of packet length (bytes).
5. `payload_entropy`: Shannon entropy of concatenated flow payloads (0–8 bits).
6. `syn_ratio`: Ratio of TCP SYN packets to total flow packet count ($[0, 1]$).

### Expanded Metadata Schema (V2 - 25 Attributes)
Enhanced flow and protocol metadata for deeper representation:
- Temporal: `flow_duration`, `iat_mean`, `iat_std`, `iat_min`, `iat_max`
- Volume: `packet_count`, `byte_count`, `packets_per_second`, `bytes_per_second`
- Directional: `forward_packet_count`, `backward_packet_count`, `forward_bytes`, `backward_bytes`
- Packet Sizes: `pkt_len_mean`, `pkt_len_std`, `pkt_len_min`, `pkt_len_max`
- Protocol & State: `syn_count`, `rst_count`, `fin_count`, `syn_ratio`, `payload_entropy`, `src_port`, `dst_port`, `protocol`

---

## 3. Specialized Detection Ensembles

GeoGuards avoids forcing all network anomalies into a rigid 4-class classifier by deploying dedicated detection engines for the **6 Problem Statement Threat Classes**:

1. **Volumetric / Protocol DDoS (`DDoSDetector`):**
   - High SYN ratio ($>0.80$), burst packet rate, small uniform packet sizes, high UDP PPS.
2. **Botnet C2 Beaconing (`C2BeaconDetector`):**
   - Inter-arrival time coefficient of variation ($CV < 0.25$), low jitter, periodic interval window, small keepalive packets.
3. **DGA Domains & DNS Tunnelling (`DNSTunnelDetector`):**
   - Subdomain Shannon entropy ($>3.6$ bits), query length ($>30$ chars), high query rate, character n-gram TF-IDF logistic regression classifier.
4. **Malware in Encrypted Sessions (`EncryptedTrafficDetector`):**
   - Metadata-only inspection of TLS/QUIC channels: packet size sequence variance, SNI entropy, handshake timing patterns without payload decryption.
5. **Reconnaissance & Port Scanning (`ReconScanDetector`):**
   - Short probe flows ($1-4$ packets), high SYN-to-data ratio, elevated TCP RST rates, fan-out host/port indexing.
6. **Data Exfiltration (`DataExfiltrationDetector`):**
   - Severe unilateral byte asymmetry (outbound/inbound ratio $>4.0$), sustained outbound volume ($>500$ KB), high payload entropy on bulk flow.

---

## 4. How to Reproduce Training & Evaluation

All preprocessing, training, and benchmarking scripts are fully automated:

```bash
# 1. Audit local datasets and generate manifest
python ml/scripts/audit_datasets.py

# 2. Preprocess data and generate leakage-safe splits
python ml/scripts/preprocess_data.py

# 3. Train Model V1, V2, Isolation Forest, and DGA classifier
python ml/scripts/train_models.py

# 4. Run throughput and bounded-latency benchmarks
python backend/benchmark.py
```

---

## 5. Measured Evaluation Summary

| Model / Component | Accuracy | Macro F1 | Weighted F1 | Avg Latency | P95 Latency |
|---|---|---|---|---|---|
| **DiodeThreatNet V1 (Baseline)** | **97.21%** | **0.9112** | **0.9710** | **0.074 ms** | **0.117 ms** |
| **DiodeThreatNet V2 (Expanded)** | **99.00%** | **0.9560** | **0.9895** | **0.114 ms** | **0.216 ms** |
| **DGA Domain Classifier** | **92.07%** | **0.9192** | - | **0.420 ms** | **0.650 ms** |
| **Full Multi-Signal Pipeline** | - | - | - | **6.833 ms** | **10.723 ms** |

---

## 6. One-Way Architecture & Passive Guarantees

- **No Active Probing:** GeoGuards contains zero ping, port scan, or reverse connection logic.
- **Physical Diode Compatibility:** Tested on passive tapped PCAP captures and streaming packet replays.
- **Explainability First:** Every alert emitted contains a structured `evidence` array containing measurable forensic observations and interpretations.
