# SIH 26145 — Passive Cyber Intelligence Prototype

**Smart India Hackathon 2026 · Problem Statement 26145**
**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**

---

## Architecture

```
Unidirectional Traffic (PCAP or Simulator)
        ↓
  Flow Extraction
  (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol)
  + flow timeout + bidirectional tracking
        ↓
  Feature Engineering
  (21 features per flow)
        ↓
  ┌─────────────────────────────────────────────────┐
  │               PARALLEL DETECTION                │
  │                                                 │
  │  ① Supervised Classifier                       │
  │     DiodeThreatNet (PyTorch, 6 features)        │
  │     4 classes: Benign / SYN-UDP Flood /         │
  │     DNS Tunneling / C2 Beaconing                │
  │                                                 │
  │  ② Anomaly Detector                            │
  │     Isolation Forest (scikit-learn, 10 features)│
  │     Scores deviation from benign baseline       │
  │                                                 │
  │  ③ Behaviour Analytics                         │
  │     Statistical heuristics                     │
  │     Detects: C2 Beaconing, DNS Tunnelling,     │
  │     Slow/Low-and-Slow patterns                 │
  └─────────────────────────────────────────────────┘
        ↓
  Risk Fusion Engine
  (configurable weighted score: w1=0.50, w2=0.25, w3=0.25)
        ↓
  Explainable Alert
  (evidence list + plain-language explanation)
        ↓
  MongoDB (persistent) / In-memory fallback
        ↓
  REST API  →  Next.js SOC Dashboard
```

The system is **PASSIVE**. No outbound probing, scanning, pinging, or
active response is performed toward the protected network.

---

## Prerequisites

- Python ≥ 3.10
- Node.js ≥ 18
- MongoDB (optional — system falls back to in-memory storage)

---

## Setup

### 1. Clone and configure

```bash
git clone <repo-url>
cd sih-diode-defense-main
```

### 2. Backend dependencies

```bash
cd backend
pip install -r ../requirements.txt
```

> **Note**: PyTorch is listed in `requirements.txt`. For GPU support,
> install it separately from https://pytorch.org/get-started/locally/

### 3. Environment configuration

```bash
# Copy the example and edit as needed
cp .env.example .env
```

Edit `backend/.env`:

```env
# MongoDB (leave blank to use in-memory storage — no database required for demo)
MONGO_URL=

# Paths to model artifacts (already present in backend/)
MODEL_PATH=diode_threat_model.pth
SCALER_PATH=scaler.pkl

# CORS origins for the dashboard
CORS_ORIGINS=http://localhost:3000
```

**Never commit `.env` with real credentials.**

### 4. Frontend dependencies

```bash
cd frontend
npm install
```

---

## Running

### Backend

```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

API docs: http://127.0.0.1:8000/docs

### Frontend

```bash
cd frontend
npm run dev
```

Dashboard: http://localhost:3000

---

## Demo Commands

### Option A — Dashboard Demo Mode (recommended)

1. Start backend + frontend as above
2. Open http://localhost:3000
3. Click **▶ Inject Flows** in the Demo Mode panel
4. Select mode (Mixed / SYN Flood / DNS Tunnel / C2 Beacon / Normal)
5. Watch alerts appear in real time

### Option B — Command-line Simulator

```bash
cd backend

# Mixed scenario (cycles all attack types)
python simulate_traffic.py --mode mixed --count 20

# Individual scenarios
python simulate_traffic.py --mode syn_flood  --count 5
python simulate_traffic.py --mode dns_tunnel --count 5
python simulate_traffic.py --mode c2_beacon  --count 5
python simulate_traffic.py --mode normal     --count 10

# Slower injection (1 second between flows)
python simulate_traffic.py --mode mixed --count 20 --delay 1.0
```

### Option C — PCAP Analysis

```bash
cd backend

# Analyse the included sample PCAP
python pcap_analyzer.py traffic_sample.pcap

# Analyse a custom PCAP
python pcap_analyzer.py /path/to/capture.pcap

# Against a remote API
python pcap_analyzer.py capture.pcap --api http://192.168.1.10:8000
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/analyze-flow` | Submit a flow for analysis |
| GET  | `/api/v1/alerts` | Retrieve recent threat alerts |
| GET  | `/api/v1/alerts/{id}` | Get a specific alert by ID |
| GET  | `/api/v1/stats` | Operational counters (real values only) |
| GET  | `/api/v1/health` | Health check |

Full interactive docs at: http://127.0.0.1:8000/docs

---

## Evaluation (when labeled data is available)

```bash
cd backend
python evaluate.py --data test_data.csv
python evaluate.py --data test_data.csv --output results.txt
```

CSV format:
```
iat_mean,iat_std,pkt_len_mean,pkt_len_std,payload_entropy,syn_ratio,label
0.05,0.02,500,80,5.0,0.02,Benign
0.0003,0.00005,64,2,0.15,0.99,SYN/UDP Flood
```

Results are clearly labelled **BASELINE** (current 6-feature model).

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_URL` | *(empty)* | MongoDB connection string. Empty = in-memory fallback |
| `MODEL_PATH` | `diode_threat_model.pth` | PyTorch model file path |
| `SCALER_PATH` | `scaler.pkl` | scikit-learn scaler file path |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `API_URL` | `http://127.0.0.1:8000` | API base URL for simulator/PCAP analyzer |

---

## Known Limitations

1. **Prototype-level analytics** — not production-hardened or performance-tested at scale.
2. **No physical diode enforcement** — the software indicator is informational only. Physical one-way isolation requires dedicated hardware.
3. **Encrypted payload opacity** — payload entropy is computed from bytes; semantic content of TLS/encrypted traffic is not inspectable.
4. **Limited attack taxonomy** — 4 classes only (Benign, SYN/UDP Flood, DNS Tunneling, C2 Beaconing). Many attack families are not modeled.
5. **Synthetic baseline** — the Isolation Forest anomaly detector is fitted on synthetic benign data. Real benign traffic should be used before deployment.
6. **Behaviour analytics are heuristic** — thresholds are approximate starting points, not scientifically validated values.
7. **No retraining in this version** — the baseline DiodeThreatNet model (v1.0) is preserved as-is. Enhanced retraining on a larger, properly labeled dataset is future work.
8. **In-memory storage is ephemeral** — alerts are lost on backend restart if MongoDB is not configured.

---

## File Structure

```
sih-diode-defense-main/
├── backend/
│   ├── main.py                  # FastAPI app + three-pillar detection pipeline
│   ├── anomaly_detector.py      # Isolation Forest anomaly detection
│   ├── behaviour_analytics.py   # Statistical behaviour heuristics
│   ├── risk_fusion.py           # Risk fusion engine
│   ├── pcap_analyzer.py         # 5-tuple flow extraction + PCAP pipeline
│   ├── simulate_traffic.py      # Deterministic demo traffic simulator
│   ├── evaluate.py              # Evaluation scaffolding
│   ├── diode_threat_model.pth   # Trained PyTorch classifier (baseline)
│   ├── scaler.pkl               # Feature scaler
│   ├── traffic_sample.pcap      # Sample PCAP for testing
│   ├── .env                     # Local environment (not committed)
│   └── .env.example             # Environment template
├── frontend/
│   └── app/
│       ├── page.tsx             # SOC Dashboard (real data only)
│       ├── layout.tsx           # App layout + metadata
│       └── globals.css          # Design system + animations
├── requirements.txt             # Python backend dependencies
├── README.md                    # This file
└── REPORT.md                    # Implementation report
```
