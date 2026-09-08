# GeoGuards — Passive Cyber Intelligence for Unidirectional Networks

**Smart India Hackathon 2026 · Problem Statement 26145**
**Theme: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**
**Team: Innov8**

---

## 🛡️ Executive Summary

GeoGuards is an AI-assisted passive cyber threat intelligence command center engineered specifically for **unidirectional network environments (data diodes)**. It ingests mirror traffic copies, extracts 5-tuple flow metadata, and executes a parallel 3-pillar detection consensus without ever sending return traffic or actively probing the protected network.

```
Unidirectional Traffic Copy (PCAP or Synthetic Ingestion)
                         ↓
               5-Tuple Flow Extraction
          (src_ip, dst_ip, src_port, dst_port, proto)
                         ↓
             21 Flow Metadata Features
                         ↓
  ┌─────────────────────────────────────────────────────────┐
  │              PARALLEL 3-PILLAR DETECTION                │
  │                                                         │
  │  ① Supervised Classifier                                │
  │     DiodeThreatNet (PyTorch MLP, 6 flow features)       │
  │     4 classes: Benign, SYN/UDP Flood,                   │
  │     DNS Tunneling, C2 Beaconing                         │
  │                                                         │
  │  ② Anomaly Detection                                    │
  │     Isolation Forest (scikit-learn, 10 features)        │
  │     Flags outlier deviations from benign baseline       │
  │                                                         │
  │  ③ Behaviour Analytics                                  │
  │     Domain heuristics for C2 Beacon regularity,         │
  │     DNS entropy/length, and Low-and-Slow scans          │
  └─────────────────────────────────────────────────────────┘
                         ↓
                 Risk Fusion Engine
     (Baseline weights: 50% Classifier · 25% Anomaly · 25% Behaviour)
                         ↓
                 Explainable Alert
         (Plain-language calibrated explanation + evidence)
                         ↓
          FastAPI Backend → Next.js SOC Dashboard
```

> [!IMPORTANT]
> **Strict Passive Monitoring**: GeoGuards performs passive metadata observation only. No outbound scanning, pinging, or active response traffic is ever generated toward the protected network.
>
> **Software Prototype Indicator**: Physical one-way isolation requires dedicated data-diode hardware. The return traffic counter confirms 0 active response packets generated.

---

## 🚀 5-Minute SIH Demo Sequence

1. **Overview Dashboard (`/`)**:
   - Inspect the **One-Way Network Topology** card showing 0 return packets.
   - Verify **System Operational** and **One-Way Ingestion** status pills in the TopBar.
2. **Instant Attack Simulator (`/` or `/demo`)**:
   - Click **"🔴 SYN Flood"** in the Overview quick bar: Watch the real-time risk chart spike and new alert appear.
   - Click **"🔵 DNS Tunnel"**: Observe high payload entropy detection on UDP port 53.
   - Click **"🟠 C2 Beacon"**: Observe periodic interval jitter analysis flagging beacon behavior.
3. **Alert Investigation Drawer (`/threats`)**:
   - Click any alert row to slide open the **Investigation Drawer**.
   - Inspect the 3-pillar breakdown (Classifier confidence %, Anomaly score %, Behaviour score %).
   - Review the verbatim backend evidence items and probabilistic analyst explanation.
4. **Detection Engine Architecture (`/detection`)**:
   - Review the mathematical consensus formula: `final_risk = 0.50 × classifier + 0.25 × anomaly + 0.25 × behaviour`.
   - Review the honest breakdown of **Implemented Baseline** vs **Future Production Roadmap**.
5. **PCAP Analysis (`/pcap`)**:
   - Drag and drop any `.pcap` capture file to execute passive offline flow reconstruction.

---

## 🛠️ Quick Start

### Backend (FastAPI)

```bash
cd backend
pip install -r ../requirements.txt

# Start backend daemon
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
- API Endpoint: `http://localhost:8000`
- Swagger Docs: `http://localhost:8000/docs`

### Frontend (Next.js 16)

```bash
cd frontend
npm install
npm run dev
```
- Dashboard: `http://localhost:3000`

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Backend status, model version, and storage mode |
| `GET` | `/api/v1/stats` | Real operational telemetry counters |
| `GET` | `/api/v1/alerts` | Paginated threat alerts stream |
| `GET` | `/api/v1/flows` | All ingested flows including benign baseline |
| `POST` | `/api/v1/analyze-flow` | Process 5-tuple flow through 3-pillar pipeline |
| `POST` | `/api/v1/analyze-pcap` | Upload `.pcap` for offline flow extraction |

---

## ⚖️ Technical Honesty & Calibrated Metrics

- **Baseline Model**: DiodeThreatNet v1.0 is a synthetic attack-baseline classifier. Accuracy and F1 metrics on production traffic are subject to future real-world dataset calibration.
- **Probabilistic Explanations**: Detections are framed as indicators ("consistent with", "suggestive of") rather than absolute proof of attacker intent.
- **Fusion Weights**: Baseline weights (50% / 25% / 25%) represent prototype starting points.

---

## 📁 Repository Structure

```
sih-diode-defense-main/
├── backend/
│   ├── main.py                  # FastAPI application & endpoints
│   ├── anomaly_detector.py      # Isolation Forest anomaly engine
│   ├── behaviour_analytics.py   # Statistical heuristic engine
│   ├── risk_fusion.py           # Multi-pillar risk consensus fusion
│   ├── pcap_analyzer.py         # Scapy flow extraction & PCAP processor
│   ├── simulate_traffic.py      # Synthetic traffic generator
│   ├── diode_threat_model.pth   # PyTorch DiodeThreatNet baseline weights
│   └── scaler.pkl               # Standard feature scaler
├── frontend/
│   ├── app/
│   │   ├── page.tsx             # Overview SOC Dashboard
│   │   ├── threats/             # Threats Feed with severity filter
│   │   ├── flows/               # Flow Explorer with 21 features
│   │   ├── detection/           # Detection Engine & Consensus weights
│   │   ├── analytics/           # Risk distribution & telemetry
│   │   ├── pcap/                # Offline PCAP upload forensic suite
│   │   ├── demo/                # Controlled Synthetic Attack Lab
│   │   ├── monitor/             # Real-time passive stream monitor
│   │   └── components/          # Reusable glassmorphic SOC components
│   └── package.json
└── README.md
```
