"""
main.py
-------
FastAPI backend for SIH 26145 — Passive Cyber Intelligence Prototype.

Architecture:
  Flow → Feature Engineering → Parallel Detection
    ├── Supervised Classifier  (DiodeThreatNet, PyTorch)
    ├── Anomaly Detector       (IsolationForest)
    └── Behaviour Analytics    (Statistical heuristics)
  → Risk Fusion Engine → Explainable Alert → MongoDB / in-memory

The system is PASSIVE. No outbound probing or active response is performed.

Environment variables (see .env.example):
  MONGO_URL       MongoDB connection string (optional — falls back to memory)
  MODEL_PATH      Path to .pth model file
  SCALER_PATH     Path to scaler.pkl
  CORS_ORIGINS    Comma-separated allowed origins
  API_URL         Base URL of this API (used by simulator/pcap analyzer)
"""

import os
import time
import uuid
import logging
import tempfile
from collections import deque
from datetime import datetime, timezone

import numpy as np
import torch
import torch.nn as nn
import joblib

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# ── Load environment ───────────────────────────────────────────────────────────
load_dotenv()   # reads .env from cwd or parent

MONGO_URL    = os.getenv("MONGO_URL",    "")
MODEL_PATH   = os.getenv("MODEL_PATH",   "diode_threat_model.pth")
SCALER_PATH  = os.getenv("SCALER_PATH",  "scaler.pkl")
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")]

logging.basicConfig(
    level   = logging.INFO,
    format  = "%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── Model version metadata ────────────────────────────────────────────────────
MODEL_VERSION = "DiodeThreatNet-v1.0-baseline"

# ── App setup ─────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "SIH 26145 — Passive Cyber Intelligence API",
    description = (
        "Passive unidirectional network threat detection for PS 26145. "
        "No active response or outbound probing is performed."
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
        db = _motor_client.nids_database
        _db_available = True
        log.info("MongoDB configured — alerts will be persisted.")
    except Exception as exc:
        log.warning("MongoDB unavailable (%s). Using in-memory fallback.", exc)
else:
    log.info("MONGO_URL not set — using in-memory alert storage.")

# In-memory fallback (always maintained for stats)
_mem_alerts : deque = deque(maxlen=500)   # non-benign alerts for threat feed
_mem_flows  : deque = deque(maxlen=1000)  # all flows (including benign) for explorer

# ── Operational counters ──────────────────────────────────────────────────────
_stats = {
    "flows_processed"          : 0,
    "threats_detected"         : 0,
    "high_risk_alerts"         : 0,
    "anomaly_count"            : 0,
    "total_inference_latency_ms": 0.0,
    "started_at"               : datetime.now(timezone.utc).isoformat(),
}

# ── Model definition (must match training) ────────────────────────────────────
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

# ── Load model & scaler ───────────────────────────────────────────────────────
log.info("Loading model from: %s", MODEL_PATH)
try:
    _model = DiodeThreatNet()
    # Try weights_only=True first (safer, PyTorch >= 2.0)
    # Fall back to legacy load for models saved with older PyTorch versions
    try:
        state = torch.load(MODEL_PATH, map_location="cpu", weights_only=True)
    except Exception:
        log.warning(
            "weights_only=True failed — retrying with legacy loader "
            "(model may have been saved with PyTorch < 2.0)."
        )
        state = torch.load(MODEL_PATH, map_location="cpu")  # noqa: S614
    _model.load_state_dict(state)
    _model.eval()
    log.info("Model loaded successfully.")
except FileNotFoundError:
    log.error("Model file not found: %s — check MODEL_PATH in .env", MODEL_PATH)
    raise
except Exception as exc:
    log.error("Failed to load model: %s", exc)
    raise

log.info("Loading scaler from: %s", SCALER_PATH)
try:
    _scaler = joblib.load(SCALER_PATH)
    log.info("Scaler loaded successfully.")
except FileNotFoundError:
    log.error("Scaler file not found: %s — check SCALER_PATH in .env", SCALER_PATH)
    raise
except Exception as exc:
    log.error("Failed to load scaler: %s", exc)
    raise

CLASS_NAMES = ["Benign", "SYN/UDP Flood", "DNS Tunneling", "C2 Beaconing"]

# ── Detection engines ─────────────────────────────────────────────────────────
from anomaly_detector    import get_detector
from behaviour_analytics import get_engine   as get_behaviour_engine
from risk_fusion         import get_fusion_engine

_anomaly_det  = get_detector()
_behav_eng    = get_behaviour_engine()
_fusion_eng   = get_fusion_engine()
log.info("Detection engines initialised.")

# ── Request schema ────────────────────────────────────────────────────────────
class IngestFlow(BaseModel):
    # Identifiers
    source_ip        : str   = Field(...,  description="Source IP address")
    destination_ip   : str   = Field("0.0.0.0", description="Destination IP address")
    source_port      : int   = Field(0,    ge=0, le=65535)
    destination_port : int   = Field(0,    ge=0, le=65535)
    protocol         : int   = Field(0,    description="IP protocol number (6=TCP, 17=UDP)")

    # Baseline 6 features (required by DiodeThreatNet)
    iat_mean         : float = Field(...,  ge=0.0)
    iat_std          : float = Field(...,  ge=0.0)
    pkt_len_mean     : float = Field(...,  ge=0.0)
    pkt_len_std      : float = Field(...,  ge=0.0)
    payload_entropy  : float = Field(...,  ge=0.0, le=8.0)
    syn_ratio        : float = Field(...,  ge=0.0, le=1.0)

    # Extended features (optional — used by anomaly & behaviour engines)
    tcp_rst_ratio    : float = Field(0.0,  ge=0.0, le=1.0)
    tcp_fin_ratio    : float = Field(0.0,  ge=0.0, le=1.0)
    duration         : float = Field(0.0,  ge=0.0, description="Flow duration in seconds")
    packet_count     : int   = Field(0,    ge=0)
    byte_count       : int   = Field(0,    ge=0)
    forward_pkts     : int   = Field(0,    ge=0)
    backward_pkts    : int   = Field(0,    ge=0)
    forward_bytes    : int   = Field(0,    ge=0)
    backward_bytes   : int   = Field(0,    ge=0)


# ── Analysis endpoint ─────────────────────────────────────────────────────────
@app.post("/api/v1/analyze-flow", summary="Analyse a single network flow")
async def analyze_flow(flow: IngestFlow):
    t_start = time.perf_counter()

    # 1. Supervised classification (baseline model — 6 features)
    raw_feats = np.array([[
        flow.iat_mean, flow.iat_std,
        flow.pkt_len_mean, flow.pkt_len_std,
        flow.payload_entropy, flow.syn_ratio,
    ]])
    scaled_feats = _scaler.transform(raw_feats)
    tensor_in    = torch.tensor(scaled_feats, dtype=torch.float32)

    with torch.no_grad():
        logits    = _model(tensor_in)
        probs     = torch.softmax(logits, dim=1).numpy()[0]
        pred_idx  = int(np.argmax(probs))
        confidence = float(probs[pred_idx])

    prediction = CLASS_NAMES[pred_idx]

    # 2. Anomaly detection
    feat_dict = flow.model_dump()
    anomaly_result = _anomaly_det.score(feat_dict)

    # 3. Behaviour analytics
    behav_result = _behav_eng.analyse(feat_dict)

    # 4. Risk fusion
    fusion = _fusion_eng.fuse(
        supervised_prediction = prediction,
        supervised_confidence = confidence,
        anomaly_score         = anomaly_result["anomaly_score"],
        behaviour_score       = behav_result.behaviour_score,
        behaviour_type        = behav_result.behaviour_type,
        behaviour_evidence    = behav_result.evidence,
    )

    t_end              = time.perf_counter()
    inference_latency  = round((t_end - t_start) * 1000, 3)   # ms

    # 5. Build alert document
    alert_id = str(uuid.uuid4())
    alert = {
        "alert_id"          : alert_id,
        "timestamp"         : datetime.now(timezone.utc).isoformat(),
        "model_version"     : MODEL_VERSION,

        # Flow identity
        "source_ip"         : flow.source_ip,
        "destination_ip"    : flow.destination_ip,
        "source_port"       : flow.source_port,
        "destination_port"  : flow.destination_port,
        "protocol"          : flow.protocol,

        # Classifier output
        "prediction"        : prediction,
        "confidence"        : round(confidence, 4),

        # Anomaly detection
        "anomaly_score"     : anomaly_result["anomaly_score"],
        "is_anomaly"        : anomaly_result["is_anomaly"],

        # Behaviour analytics
        "behaviour_score"   : behav_result.behaviour_score,
        "behaviour_type"    : behav_result.behaviour_type,

        # Fusion output
        "final_risk_score"  : fusion.final_risk_score,
        "severity"          : fusion.severity,
        "dominant_threat"   : fusion.dominant_threat,
        "evidence"          : fusion.evidence,
        "explanation"       : fusion.explanation,

        # Performance
        "inference_latency_ms": inference_latency,

        # Raw flow features (for audit)
        "features"          : {
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

    # 6. Update counters
    _stats["flows_processed"] += 1
    _stats["total_inference_latency_ms"] += inference_latency
    if prediction != "Benign" or fusion.dominant_threat != "Benign":
        _stats["threats_detected"] += 1
    if fusion.severity in ("HIGH", "CRITICAL"):
        _stats["high_risk_alerts"] += 1
    if anomaly_result["is_anomaly"]:
        _stats["anomaly_count"] += 1

    # 7. Store alert
    _mem_flows.appendleft(alert)   # all flows → Flow Explorer
    _mem_alerts.appendleft(alert)  # kept for backward compat (filters applied at read time)
    if _db_available and db is not None and fusion.dominant_threat != "Benign":
        try:
            db_doc = {k: v for k, v in alert.items() if k != "alert_id"}
            db_doc["_id"] = alert_id
            await db.alerts.insert_one(db_doc)
        except Exception as exc:
            log.warning("MongoDB write failed: %s", exc)

    # Remove internal MongoDB _id from response
    return {k: v for k, v in alert.items()}


# ── Alerts endpoint ────────────────────────────────────────────────────────────
@app.get("/api/v1/alerts", summary="Retrieve recent alerts (threats only)")
async def get_alerts(limit: int = 50):
    # Try DB first, fall back to memory
    if _db_available and db is not None:
        try:
            cursor = db.alerts.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit)
            alerts = await cursor.to_list(length=limit)
            if alerts:
                return alerts
        except Exception as exc:
            log.warning("MongoDB read failed (%s), using memory.", exc)

    # Return from in-memory store (filter to non-benign for dashboard)
    mem = [a for a in _mem_alerts if a.get("dominant_threat", "Benign") != "Benign"]
    return mem[:limit]


# ── Alert detail endpoint ─────────────────────────────────────────────────────
@app.get("/api/v1/alerts/{alert_id}", summary="Get a specific alert by ID")
async def get_alert(alert_id: str):
    # Search memory first
    for a in _mem_alerts:
        if a.get("alert_id") == alert_id:
            return a
    # Try DB
    if _db_available and db is not None:
        try:
            doc = await db.alerts.find_one({"_id": alert_id}, {"_id": 0})
            if doc:
                return doc
        except Exception as exc:
            log.warning("MongoDB find_one failed: %s", exc)
    raise HTTPException(status_code=404, detail="Alert not found")


# ── Stats endpoint ────────────────────────────────────────────────────────────
@app.get("/api/v1/stats", summary="Operational statistics (real counters only)")
async def get_stats():
    flows      = _stats["flows_processed"]
    total_lat  = _stats["total_inference_latency_ms"]
    avg_lat    = round(total_lat / flows, 3) if flows > 0 else None

    return {
        "flows_processed"         : flows,
        "threats_detected"        : _stats["threats_detected"],
        "high_risk_alerts"        : _stats["high_risk_alerts"],
        "anomaly_count"           : _stats["anomaly_count"],
        "average_inference_latency_ms": avg_lat,
        "storage_backend"         : "mongodb" if _db_available else "in-memory",
        "model_version"           : MODEL_VERSION,
        "started_at"              : _stats["started_at"],
    }


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/api/v1/health", summary="Health check")
async def health():
    return {
        "status"        : "ok",
        "model_loaded"  : True,
        "scaler_loaded" : True,
        "db_available"  : _db_available,
        "model_version" : MODEL_VERSION,
    }


# ── All flows endpoint (for Flow Explorer) ────────────────────────────────────
@app.get("/api/v1/flows", summary="Retrieve recent flows (all, including benign)")
async def get_flows(limit: int = 100):
    """
    Returns all recently analyzed flows including benign traffic.
    Used by the Flow Explorer to let analysts inspect the full traffic picture.
    """
    return list(_mem_flows)[:limit]


# ── PCAP upload endpoint ──────────────────────────────────────────────────────
@app.post("/api/v1/analyze-pcap", summary="Upload and analyze a PCAP file")
async def analyze_pcap_upload(file: UploadFile = File(...)):
    """
    Accept a .pcap file upload, extract flows using 5-tuple grouping,
    run each flow through the full detection pipeline, and return results.

    This is a synchronous endpoint suitable for small PCAP files (prototype use).
    For large captures, use the CLI: python pcap_analyzer.py <file>
    """
    if not file.filename or not file.filename.lower().endswith(".pcap"):
        raise HTTPException(
            status_code=400,
            detail="Only .pcap files are supported. Upload a valid packet capture file."
        )

    # Write upload to a temporary file
    try:
        content = await file.read()
        if len(content) == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(content)
            tmp_path = tmp.name

        log.info("PCAP upload: %s (%d bytes) → temp file %s", file.filename, len(content), tmp_path)
    except HTTPException:
        raise
    except Exception as exc:
        log.error("Failed to save uploaded PCAP: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to save PCAP: {exc}")

    # Import and run the PCAP analysis inline
    try:
        from pcap_analyzer import analyze_pcap_to_list
        flows = analyze_pcap_to_list(tmp_path)
    except ImportError:
        # Fallback: pcap_analyzer module available but analyze_pcap_to_list not yet defined
        # In that case scapy might not be installed — return a clear error
        raise HTTPException(
            status_code=503,
            detail="PCAP analysis requires scapy. Install with: pip install scapy"
        )
    except Exception as exc:
        log.error("PCAP analysis failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"PCAP analysis failed: {exc}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    if not flows:
        return {"message": "No analyzable flows found in PCAP.", "results": [], "flow_count": 0}

    # Run each flow through the detection pipeline
    results = []
    for feat in flows:
        try:
            # Validate required fields exist
            flow_obj = IngestFlow(
                source_ip        = feat.get("source_ip", "0.0.0.0"),
                destination_ip   = feat.get("destination_ip", "0.0.0.0"),
                source_port      = feat.get("source_port", 0),
                destination_port = feat.get("destination_port", 0),
                protocol         = feat.get("protocol", 0),
                iat_mean         = feat.get("iat_mean", 0.0),
                iat_std          = feat.get("iat_std", 0.0),
                pkt_len_mean     = feat.get("pkt_len_mean", 0.0),
                pkt_len_std      = feat.get("pkt_len_std", 0.0),
                payload_entropy  = min(feat.get("payload_entropy", 0.0), 8.0),
                syn_ratio        = min(feat.get("syn_ratio", 0.0), 1.0),
                tcp_rst_ratio    = min(feat.get("tcp_rst_ratio", 0.0), 1.0),
                tcp_fin_ratio    = min(feat.get("tcp_fin_ratio", 0.0), 1.0),
                duration         = feat.get("duration", 0.0),
                packet_count     = feat.get("packet_count", 0),
                byte_count       = feat.get("byte_count", 0),
                forward_pkts     = feat.get("forward_pkts", 0),
                backward_pkts    = feat.get("backward_pkts", 0),
                forward_bytes    = feat.get("forward_bytes", 0),
                backward_bytes   = feat.get("backward_bytes", 0),
            )
            # Reuse the main analysis logic via internal call
            result = await analyze_flow(flow_obj)
            results.append(result)
        except Exception as exc:
            log.warning("Failed to analyze PCAP flow: %s", exc)

    return {
        "message"    : f"Analyzed {len(results)} flows from {file.filename}",
        "flow_count" : len(results),
        "results"    : results,
    }