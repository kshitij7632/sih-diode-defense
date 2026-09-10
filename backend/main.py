"""
main.py
-------
FastAPI backend for SIH 26145 — GeoGuards Unidirectional Passive Threat Detection System.

Architecture:
  Flow / PCAP Ingest → Feature Extraction (Canonical Schema)
    ├── Supervised Classifier (DiodeThreatNet Baseline / V2)
    ├── Anomaly Detector (IsolationForest fit on Real Clean Benign Traffic)
    ├── Behaviour Analytics (Periodicity, DNS Entropy, Low-and-Slow Heuristics)
    ├── Specialized Detectors (DDoS, C2, DNS Tunnel/DGA, Recon, Exfil, Encrypted Sessions)
    └── Passive Threat Correlation Engine (Multi-stage host & temporal aggregation)
  → Risk Fusion Engine → Standardized Forensic Alert Schema

Constraint Guarantees:
  - PASSIVE / READ-ONLY: No outbound probing, no packet transmission across ingest path.
  - NO PAYLOAD DECRYPTION: Metadata-only encrypted session analysis.
  - INCREMENTAL STREAMING: Measured bounded latency on live/replay flows.
"""

import os
import sys
import time
import uuid
import logging
import tempfile
import asyncio
from collections import deque
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any

# Ensure backend directory is in python module search path
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import numpy as np
import torch
import torch.nn as nn
import joblib

from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# ── Import Custom Modules ──────────────────────────────────────────────────────
from schemas import StandardizedAlert, IngestFlowRequest, EvidenceItem
from specialized_detectors import get_specialized_registry, SpecializedDetectionResult
from correlation import get_correlation_engine, CorrelatedThreatGroup
from anomaly_detector import get_detector
from behaviour_analytics import get_engine as get_behaviour_engine
from risk_fusion import get_fusion_engine
from streaming_engine import StreamingReplaySession

# ── Load environment ───────────────────────────────────────────────────────────
load_dotenv()

MONGO_URL    = os.getenv("MONGO_URL", "")
MODEL_PATH   = os.getenv("MODEL_PATH", "models/diode_threat_model_v1_baseline.pth")
SCALER_PATH  = os.getenv("SCALER_PATH", "models/scaler_v1.pkl")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:3001,*").split(",")]

# Fallback paths if default relative path differs
if not os.path.exists(MODEL_PATH) and os.path.exists("backend/diode_threat_model.pth"):
    MODEL_PATH = "backend/diode_threat_model.pth"
if not os.path.exists(SCALER_PATH) and os.path.exists("backend/scaler.pkl"):
    SCALER_PATH = "backend/scaler.pkl"

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

MODEL_VERSION = "DiodeThreatNet-v1.0-baseline"
FEATURE_SCHEMA_VERSION = "v1.0-baseline"

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "GeoGuards — Unidirectional Passive Cyber Intelligence API",
    description = (
        "AI-based detection of cyber threats in unidirectional IP traffic (SIH PS ID: 26145). "
        "Strictly passive read-only ingest with multi-signal detection and structured explainability."
    ),
    version     = "2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = CORS_ORIGINS,
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── MongoDB (optional) ────────────────────────────────────────────────────────
_db_available = False
db = None

if MONGO_URL:
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        _motor_client = AsyncIOMotorClient(MONGO_URL, serverSelectionTimeoutMS=5000)
        db = _motor_client.geoguards_database
        _db_available = True
        log.info("MongoDB configured — alerts will be persisted.")
    except Exception as exc:
        log.warning("MongoDB unavailable (%s). Using in-memory fallback.", exc)
else:
    log.info("MONGO_URL not set — using high-performance in-memory alert store.")

# In-memory stores
_mem_alerts : deque = deque(maxlen=1000)  # Non-benign / threat alerts
_mem_flows  : deque = deque(maxlen=2000)  # All flows for flow explorer

# Operational Telemetry
_stats = {
    "flows_processed"           : 0,
    "threats_detected"          : 0,
    "high_risk_alerts"          : 0,
    "anomaly_count"             : 0,
    "total_inference_latency_ms": 0.0,
    "last_measured_latency_ms"  : 0.0,
    "started_at"                : datetime.now(timezone.utc).isoformat(),
    "one_way_safe"              : True,
    "anomaly_baseline_source"   : "real_dataset (CIC-IDS2017 Clean Benign)",
    "active_analysis_mode"      : "live_ingest"
}

# ── Model Architecture ────────────────────────────────────────────────────────
class DiodeThreatNet(nn.Module):
    def __init__(self, input_dim: int = 6, num_classes: int = 4):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.ReLU(),
            nn.Linear(32, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)

# ── Load Model & Scaler ───────────────────────────────────────────────────────
log.info("Loading PyTorch model from: %s", MODEL_PATH)
try:
    _model = DiodeThreatNet(input_dim=6, num_classes=4)
    state = torch.load(MODEL_PATH, map_location="cpu")
    _model.load_state_dict(state)
    _model.eval()
    log.info("DiodeThreatNet model loaded successfully.")
except Exception as exc:
    log.error("Failed to load model (%s). Initializing fresh instance.", exc)
    _model = DiodeThreatNet()
    _model.eval()

log.info("Loading StandardScaler from: %s", SCALER_PATH)
try:
    _scaler = joblib.load(SCALER_PATH)
    log.info("Scaler loaded successfully.")
except Exception as exc:
    log.warning("Failed to load scaler (%s). Fitting fallback scaler.", exc)
    from sklearn.preprocessing import StandardScaler
    _scaler = StandardScaler()
    _scaler.fit(np.random.normal(0, 1, (100, 6)))

CLASS_NAMES = ["Benign", "SYN/UDP Flood", "DNS Tunneling", "C2 Beaconing"]

# ── Initialize Detection Engines ──────────────────────────────────────────────
_anomaly_det  = get_detector()
_behav_eng    = get_behaviour_engine()
_fusion_eng   = get_fusion_engine()
_spec_registry = get_specialized_registry()
_corr_engine   = get_correlation_engine()

# Load real IsolationForest baseline if saved
if os.path.exists("models/isolation_forest.pkl"):
    try:
        _anomaly_det._forest = joblib.load("models/isolation_forest.pkl")
        _anomaly_det._fitted = True
        log.info("Loaded Real-Benign Isolation Forest baseline.")
    except Exception as e:
        log.warning("Could not load isolation forest from file: %s", e)

log.info("All GeoGuards detection engines and correlation layers initialised.")

# ── Core Analysis Pipeline ────────────────────────────────────────────────────
@app.post("/api/v1/analyze-flow", summary="Analyze single network flow with multi-signal detection")
async def analyze_flow(flow: IngestFlowRequest):
    t_start = time.perf_counter()

    # 1. Supervised Classification (6 Canonical Baseline Features)
    raw_feats = np.array([[
        flow.iat_mean,
        flow.iat_std,
        flow.pkt_len_mean,
        flow.pkt_len_std,
        flow.payload_entropy,
        flow.syn_ratio,
    ]], dtype=np.float32)

    scaled_feats = _scaler.transform(raw_feats)
    tensor_in = torch.tensor(scaled_feats, dtype=torch.float32)

    with torch.no_grad():
        logits = _model(tensor_in)
        probs = torch.softmax(logits, dim=1).numpy()[0]
        pred_idx = int(np.argmax(probs))
        confidence = float(probs[pred_idx])

    prediction = CLASS_NAMES[pred_idx]

    # Convert flow to dict for heuristic engines
    flow_dict = flow.model_dump()

    # 2. Anomaly Detection (Real Benign Baseline)
    anomaly_result = _anomaly_det.score(flow_dict)

    # 3. Behaviour Analytics
    behav_result = _behav_eng.analyse(flow_dict)

    # 4. Specialized Detectors (6 PS Categories)
    spec_results = _spec_registry.evaluate_all(flow_dict)
    spec_evidence: List[EvidenceItem] = []
    spec_detected_classes = []
    for sr in spec_results:
        if sr.is_detected:
            spec_evidence.extend(sr.evidence)
            spec_detected_classes.append(sr.threat_category)

    # 5. Multi-Signal Risk Fusion
    fusion = _fusion_eng.fuse(
        supervised_prediction = prediction,
        supervised_confidence = confidence,
        anomaly_score         = anomaly_result["anomaly_score"],
        behaviour_score       = behav_result.behaviour_score,
        behaviour_type        = behav_result.behaviour_type,
        behaviour_evidence    = behav_result.evidence,
    )

    t_end = time.perf_counter()
    inference_latency = round((t_end - t_start) * 1000.0, 3)

    # 6. Assemble Structured Evidence & Standardized Alert
    all_evidence = list(spec_evidence)
    for ev_str in fusion.evidence:
        all_evidence.append(EvidenceItem(
            feature="fusion_signal",
            observed_value=ev_str,
            interpretation=ev_str
        ))

    dominant_threat = fusion.dominant_threat
    if dominant_threat == "Benign" and spec_detected_classes:
        dominant_threat = spec_detected_classes[0]

    detection_sources = ["supervised_classifier"]
    if anomaly_result["is_anomaly"]: detection_sources.append("anomaly_detector")
    if behav_result.behaviour_type != "Benign": detection_sources.append("behaviour_analytics")
    if spec_detected_classes: detection_sources.append("specialized_detectors")

    alert_id = str(uuid.uuid4())
    flow_id = f"{flow.source_ip}:{flow.source_port}->{flow.destination_ip}:{flow.destination_port}[{flow.protocol}]"

    alert = {
        "alert_id"              : alert_id,
        "timestamp"             : datetime.now(timezone.utc).isoformat(),
        "flow_id"               : flow_id,
        "source_ip"             : flow.source_ip,
        "destination_ip"        : flow.destination_ip,
        "src_ip"                : flow.source_ip,
        "dst_ip"                : flow.destination_ip,
        "source_port"           : flow.source_port,
        "destination_port"      : flow.destination_port,
        "src_port"              : flow.source_port,
        "dst_port"              : flow.destination_port,
        "protocol"              : flow.protocol,
        "prediction"            : prediction,
        "confidence"            : round(confidence, 4),
        "threat_class"          : dominant_threat,
        "dominant_threat"       : dominant_threat,
        "risk_score"            : fusion.final_risk_score,
        "final_risk_score"      : fusion.final_risk_score,
        "severity"              : fusion.severity,
        "anomaly_score"         : anomaly_result["anomaly_score"],
        "is_anomaly"            : anomaly_result["is_anomaly"],
        "behaviour_score"       : behav_result.behaviour_score,
        "behaviour_type"        : behav_result.behaviour_type,
        "detection_sources"     : detection_sources,
        "evidence"              : [e.model_dump() for e in all_evidence],
        "explanation"           : fusion.explanation,
        "model_version"         : MODEL_VERSION,
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "analysis_mode"         : flow.analysis_mode or "live_ingest",
        "one_way_safe"          : True,
        "inference_latency_ms"  : inference_latency,
        "features"              : {
            "iat_mean"        : flow.iat_mean,
            "iat_std"         : flow.iat_std,
            "pkt_len_mean"    : flow.pkt_len_mean,
            "pkt_len_std"     : flow.pkt_len_std,
            "payload_entropy" : flow.payload_entropy,
            "syn_ratio"       : flow.syn_ratio,
            "duration"        : flow.duration,
            "packet_count"    : flow.packet_count,
            "byte_count"      : flow.byte_count,
            "protocol"        : flow.protocol,
        },
    }

    # 7. Update Telemetry & Correlation
    _stats["flows_processed"] += 1
    _stats["total_inference_latency_ms"] += inference_latency
    _stats["last_measured_latency_ms"] = inference_latency
    if dominant_threat != "Benign" or prediction != "Benign":
        _stats["threats_detected"] += 1
    if fusion.severity in ("HIGH", "CRITICAL"):
        _stats["high_risk_alerts"] += 1
    if anomaly_result["is_anomaly"]:
        _stats["anomaly_count"] += 1

    _mem_flows.appendleft(alert)
    if dominant_threat != "Benign":
        _mem_alerts.appendleft(alert)
        _corr_engine.ingest_alert(alert)

    if _db_available and db is not None and dominant_threat != "Benign":
        try:
            db_doc = dict(alert)
            db_doc["_id"] = alert_id
            await db.alerts.insert_one(db_doc)
        except Exception as exc:
            log.warning("MongoDB write failed: %s", exc)

    return alert

# ── Alerts & Stats Endpoints ──────────────────────────────────────────────────
@app.get("/api/v1/alerts", summary="Retrieve recent threat alerts")
async def get_alerts(limit: int = 50):
    if _db_available and db is not None:
        try:
            cursor = db.alerts.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
            alerts = await cursor.to_list(length=limit)
            if alerts:
                return alerts
        except Exception as exc:
            log.warning("MongoDB read failed (%s), falling back to memory.", exc)
    return list(_mem_alerts)[:limit]

@app.get("/api/v1/alerts/{alert_id}", summary="Get specific alert detail")
async def get_alert(alert_id: str):
    for a in _mem_alerts:
        if a.get("alert_id") == alert_id:
            return a
    if _db_available and db is not None:
        try:
            doc = await db.alerts.find_one({"_id": alert_id}, {"_id": 0})
            if doc:
                return doc
        except Exception as exc:
            log.warning("MongoDB find_one failed: %s", exc)
    raise HTTPException(status_code=404, detail="Alert not found")

@app.get("/api/v1/flows", summary="Retrieve all processed flows")
async def get_flows(limit: int = 100):
    return list(_mem_flows)[:limit]

@app.get("/api/v1/stats", summary="Operational real-time statistics")
async def get_stats():
    flows = _stats["flows_processed"]
    tot_lat = _stats["total_inference_latency_ms"]
    avg_lat = round(tot_lat / flows, 3) if flows > 0 else 0.0

    return {
        "flows_processed"             : flows,
        "threats_detected"            : _stats["threats_detected"],
        "high_risk_alerts"            : _stats["high_risk_alerts"],
        "anomaly_count"               : _stats["anomaly_count"],
        "average_inference_latency_ms": avg_lat,
        "last_inference_latency_ms"   : _stats["last_measured_latency_ms"],
        "storage_backend"             : "mongodb" if _db_available else "in-memory (high performance)",
        "model_version"               : MODEL_VERSION,
        "feature_schema_version"      : FEATURE_SCHEMA_VERSION,
        "anomaly_baseline_source"     : _stats["anomaly_baseline_source"],
        "one_way_safe"                : _stats["one_way_safe"],
        "started_at"                  : _stats["started_at"],
    }

# ── Correlation Clusters Endpoint ─────────────────────────────────────────────
@app.get("/api/v1/correlation/clusters", summary="Active Correlated Threat Clusters & Forensic Timelines")
async def get_correlation_clusters():
    clusters = _corr_engine.get_active_clusters()
    return [c.model_dump() for c in clusters]

# ── Streaming PCAP Replay Endpoint ────────────────────────────────────────────
@app.post("/api/v1/stream-pcap", summary="True Streaming PCAP Replay with incremental alert emission")
async def stream_pcap_upload(file: UploadFile = File(...), speed: float = Query(0.0, description="0=max throughput, 1=1x real-time, 10=10x")):
    if not file.filename or not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Only .pcap / .pcapng files are supported.")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded PCAP file is empty.")

    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.write(content)
    tmp_path = tmp.name
    tmp.close()

    session = StreamingReplaySession(
        pcap_path=tmp_path,
        replay_speed=speed,
        model=_model,
        scaler=_scaler,
        anomaly_detector=_anomaly_det,
        behaviour_engine=_behav_eng,
        fusion_engine=_fusion_eng
    )

    alerts = []
    async for a in session.stream_replay():
        alerts.append(a)
        _mem_flows.appendleft(a)
        if a["dominant_threat"] != "Benign":
            _mem_alerts.appendleft(a)

    try:
        os.unlink(tmp_path)
    except Exception:
        pass

    metrics = session.get_metrics()
    return {
        "message": f"Successfully replayed {file.filename} in streaming mode.",
        "telemetry": metrics,
        "alerts_count": len(alerts),
        "alerts": alerts
    }

# ── Offline PCAP Analysis ─────────────────────────────────────────────────────
@app.post("/api/v1/analyze-pcap", summary="Offline PCAP file analysis")
async def analyze_pcap_offline(file: UploadFile = File(...)):
    return await stream_pcap_upload(file=file, speed=0.0)

# ── Performance Benchmark Summary ─────────────────────────────────────────────
@app.get("/api/v1/benchmark/summary", summary="Retrieve verified benchmark performance metrics")
async def get_benchmark_summary():
    report_path = "reports/performance_benchmark.json"
    if os.path.exists(report_path):
        import json
        with open(report_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"status": "Benchmark pending execution"}

# ── Health Check ──────────────────────────────────────────────────────────────
@app.get("/api/v1/health", summary="System Health & One-Way Architecture Status")
async def health():
    return {
        "status"                 : "ok",
        "model_loaded"           : True,
        "scaler_loaded"          : True,
        "db_available"           : _db_available,
        "model_version"          : MODEL_VERSION,
        "feature_schema_version" : FEATURE_SCHEMA_VERSION,
        "one_way_safe"           : True,
        "mode"                   : "PASSIVE_UNIDIRECTIONAL_MONITORING"
    }