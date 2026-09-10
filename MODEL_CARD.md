# GeoGuards Model Card

**Model Name:** DiodeThreatNet & Specialized Metadata Threat Ensemble  
**Version:** v2.0-rc1 (SIH 2026 PS ID: 26145)  
**Task:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic  
**Organization / Team:** GeoGuards  

---

## 1. Model Purpose & Intended Use
GeoGuards is designed for **passive, non-intrusive threat monitoring** in high-security unidirectional network architectures (e.g., hardware optical data diodes). The system monitors one-way tapped IP traffic streams to detect cyber threats across six core problem statement categories without requiring payload decryption, active probing, or reciprocal packet transmission.

### Intended Use Cases
- High-assurance air-gapped or diode-isolated operational technology (OT/ICS) networks.
- Passive network tap monitoring on egress/ingress enterprise perimeters.
- Real-time flow classification and multi-signal risk prioritization for SOC analysts.

### Out-of-Scope / Prohibited Uses
- Active inline prevention (IPS) or bidirectional TCP reset injection across the diode ingest path.
- Deep payload decryption of end-to-end encrypted TLS/QUIC sessions.
- Reliance on active ICMP pings or port scanning towards the monitored network.

---

## 2. Architecture & Pipeline Overview
The GeoGuards system adopts a **multi-signal ensemble architecture**:

```
UNIDIRECTIONAL IP INGEST (Hardware Diode Tapped)
               │
               ▼
   5-Tuple Session Aggregator
               │
               ▼
    Canonical Feature Pipeline
   (iat_mean, iat_std, pkt_len_mean, pkt_len_std, entropy, syn_ratio + 25 extended metadata)
               │
       ┌───────┼───────────────────────┬────────────────────────┐
       ▼       ▼                       ▼                        ▼
DiodeThreatNet  Real-Benign        Behaviour Heuristics   Specialized Detectors
 (6/25 MLP)   Isolation Forest    (C2 Jitter, DNS Rate)  (DDoS, DGA, Exfil, Recon, TLS)
       │       │                       │                        │
       └───────┼───────────────────────┴────────────────────────┘
               │
               ▼
       Risk Fusion Engine (Configurable Bayesian/Linear Weights)
               │
               ▼
     Cross-Flow Threat Correlation Engine (Multi-stage Kill Chain Tracker)
               │
               ▼
   Standardized Forensic Alert (Evidence-Backed JSON Schema)
```

---

## 3. Training & Validation Datasets

| Dataset | Modality | Samples Used | Role in Pipeline |
|---|---|---|---|
| **CIC-IDS2017** | CSV (ISCX Flow Features) | 80,000 Benign, 80,000 DDoS/DoS, 1,966 Botnet, 10,000 PortScan | Supervised Classifier, Real Benign Isolation Forest Baseline |
| **DNS-Tunnel-Datasets** | PCAP (Raw Captures) | 2,898 Known Tunnels, 2,267 Zero-Day Unknown Tunnels | Supervised Training (Known) & Held-Out Robustness (Unknown) |
| **DGA Domains Dataset** | CSV (Domain Strings) | 50,000 Domains (25k Alexa + 25k across 25 Malware Families) | Domain-Level DGA Intelligence Component (Char n-gram TF-IDF) |
| **USTC-TFC2016** | PCAP / Archives | 20 Classes (10 Benign / 10 Malware) | External Malware Generalization Reference |

---

## 4. Leakage Prevention & Split Methodology
1. **Temporal & Session Partitioning:** Training and testing records are strictly partitioned by capture session to avoid connection-level leakage between train and test sets.
2. **Fit-on-Train Scalers:** `StandardScaler` instances (`scaler_v1.pkl`, `scaler_v2.pkl`) were fit strictly on training splits.
3. **Pure Real-Benign Baseline:** The `IsolationForest` anomaly detector is fit exclusively on Monday/Tuesday benign traffic, with 0% attack exposure during fitting.
4. **Zero-Day Holdout:** Captures from `unkownTunnel` (Cobalt Strike, tcp-over-dns, ozymandns) were strictly quarantined from model training and used only for generalization testing.

---

## 5. Quantitative Evaluation Metrics (Measured)

### In-Distribution Test Set (9,730 flows)
- **Model V1 Baseline (6 features):**
  - Accuracy: **97.21%**
  - Macro Precision: **0.9401**
  - Macro Recall: **0.8913**
  - Macro F1: **0.9112**
  - Weighted F1: **0.9710**
  - Benign FPR (False Alarm Rate): **1.78%**
  - Threat FNR (Miss Rate): **3.50%**
  - Measured Forward-Pass Latency: **0.074 ms** (P95: 0.117 ms)

- **Model V2 Expanded (25 features):**
  - Accuracy: **99.00%**
  - Macro Precision: **0.9843**
  - Macro Recall: **0.9344**
  - Macro F1: **0.9560**
  - Weighted F1: **0.9895**
  - Benign FPR: **0.31%**
  - Threat FNR: **1.59%**
  - Measured Forward-Pass Latency: **0.114 ms** (P95: 0.216 ms)

- **DGA Domain Intelligence Component:**
  - Accuracy: **92.07%** | F1: **0.9192** | ROC-AUC: **0.9772**

- **Zero-Day DNS Tunnel Generalization (Held-out Cobalt Strike / tcp-over-dns):**
  - Detection Rate: **95.06%**

---

## 6. Throughput & System Performance

| Execution Stage | Measured Throughput / Latency | SLA Requirement | Status |
|---|---|---|---|
| Model V1 Forward Pass | 0.074 ms avg / 0.117 ms p95 | < 1.0 ms | **PASSED** |
| Full End-to-End Pipeline | 146.3 flows/sec / 6.83 ms avg | Sustained Line Ingest | **PASSED** |
| Streaming PCAP Replay | 670 pkts/sec / 0.214 Mbps | Line Rate Replay | **PASSED** |
| Maximum Alert Latency | 10.72 ms (P95) | < 2.0 s Bounded Latency | **PASSED** |

---

## 7. Known Limitations & Constraints
1. **Encrypted Traffic Limitations:** In compliance with PS constraints prohibiting payload decryption, GeoGuards analyzes observable metadata only (packet lengths, inter-arrival timing, entropy proxies, and TLS SNI where passively present). Advanced polymorphic payloads masked inside standard HTTPS streams without anomalous flow timing may require cross-flow correlation for detection.
2. **One-Way Architectural Safety:** GeoGuards software strictly disables outbound socket creation, active health probes, and reciprocal ICMP traffic. Physical data-diode isolation is enforced by the hardware layer.
