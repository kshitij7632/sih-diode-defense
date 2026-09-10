"""
streaming_engine.py
--------------------
Streaming PCAP Replay Engine for GeoGuards (SIH 26145).

Mandatory Requirement: Incremental processing, NOT batch.
Processes packets and flow-windows incrementally, extracts 5-tuple flows,
performs multi-signal threat detection on-the-fly, fuses risk,
and emits alerts in real-time as flows complete.

Tracks measured throughput:
- packets_processed
- flows_processed
- alerts_emitted
- elapsed_time_sec
- flows_per_sec
- mbps
- avg_inference_latency_ms
- p95_inference_latency_ms
"""

import os
import time
import math
import uuid
import logging
import asyncio
import numpy as np
from typing import Dict, Any, List, Optional, AsyncGenerator, Callable
from collections import defaultdict, deque
from datetime import datetime, timezone

from schemas import StandardizedAlert, EvidenceItem
from specialized_detectors import get_specialized_registry
from correlation import get_correlation_engine

log = logging.getLogger(__name__)

class StreamingReplaySession:
    def __init__(
        self,
        pcap_path: str,
        replay_speed: float = 0.0, # 0.0 = max throughput, 1.0 = real-time, 10.0 = 10x
        flow_timeout_sec: float = 15.0,
        model=None,
        scaler=None,
        anomaly_detector=None,
        behaviour_engine=None,
        fusion_engine=None,
        class_names=None
    ):
        self.pcap_path = pcap_path
        self.replay_speed = replay_speed
        self.flow_timeout_sec = flow_timeout_sec
        self.model = model
        self.scaler = scaler
        self.anomaly_detector = anomaly_detector
        self.behaviour_engine = behaviour_engine
        self.fusion_engine = fusion_engine
        self.class_names = class_names or ["Benign", "SYN/UDP Flood", "DNS Tunneling", "C2 Beaconing"]
        self.specialized_registry = get_specialized_registry()
        self.correlation_engine = get_correlation_engine()

        # Telemetry counters
        self.start_time = 0.0
        self.end_time = 0.0
        self.packets_processed = 0
        self.bytes_processed = 0
        self.flows_processed = 0
        self.alerts_emitted = 0
        self.latencies_ms: List[float] = []
        self.is_running = False

    def get_metrics(self) -> Dict[str, Any]:
        elapsed = max(0.0001, (self.end_time if self.end_time > 0 else time.perf_counter()) - self.start_time)
        fps = round(self.flows_processed / elapsed, 2)
        mbps = round((self.bytes_processed * 8.0) / (elapsed * 1_000_000.0), 3)
        avg_lat = round(float(np.mean(self.latencies_ms)), 3) if self.latencies_ms else 0.0
        p95_lat = round(float(np.percentile(self.latencies_ms, 95)), 3) if self.latencies_ms else 0.0
        p50_lat = round(float(np.percentile(self.latencies_ms, 50)), 3) if self.latencies_ms else 0.0

        return {
            "status": "COMPLETED" if self.end_time > 0 else ("RUNNING" if self.is_running else "IDLE"),
            "packets_processed": self.packets_processed,
            "bytes_processed": self.bytes_processed,
            "flows_processed": self.flows_processed,
            "alerts_emitted": self.alerts_emitted,
            "elapsed_time_sec": round(elapsed, 3),
            "flows_per_second": fps,
            "throughput_mbps": mbps,
            "avg_inference_latency_ms": avg_lat,
            "p50_inference_latency_ms": p50_lat,
            "p95_inference_latency_ms": p95_lat
        }

    async def stream_replay(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Incrementally reads packets, flushes timed-out or completed flows,
        runs pipeline, and yields StandardizedAlert dictionaries.
        """
        try:
            from scapy.all import PcapReader, IP, IPv6, TCP, UDP, DNS
        except ImportError:
            log.error("Scapy is required for PCAP streaming replay.")
            return

        self.is_running = True
        self.start_time = time.perf_counter()
        
        active_flows = {}
        last_pkt_time = 0.0

        try:
            pcap_reader = PcapReader(self.pcap_path)
        except Exception as e:
            log.error("Failed to open PCAP reader: %s", e)
            self.is_running = False
            return

        for pkt in pcap_reader:
            self.packets_processed += 1
            pkt_len = len(pkt)
            self.bytes_processed += pkt_len

            if not (IP in pkt or IPv6 in pkt):
                continue

            ip = pkt[IP] if IP in pkt else pkt[IPv6]
            proto = ip.proto
            src_ip, dst_ip = ip.src, ip.dst
            sport, dport = 0, 0
            is_syn, is_rst, is_fin = 0, 0, 0
            payload_b = b""
            dns_qname = None

            if TCP in pkt:
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
                flags = pkt[TCP].flags
                if flags & 0x02: is_syn = 1
                if flags & 0x04: is_rst = 1
                if flags & 0x01: is_fin = 1
                if hasattr(pkt[TCP], "payload") and bytes(pkt[TCP].payload):
                    payload_b = bytes(pkt[TCP].payload)
            elif UDP in pkt:
                sport, dport = pkt[UDP].sport, pkt[UDP].dport
                if hasattr(pkt[UDP], "payload") and bytes(pkt[UDP].payload):
                    payload_b = bytes(pkt[UDP].payload)

            if DNS in pkt and pkt[DNS].qd:
                try:
                    dns_qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                except Exception:
                    pass

            pkt_time = float(pkt.time)
            
            # Simulated timing delay for replay pacing if requested
            if self.replay_speed > 0 and last_pkt_time > 0:
                dt = (pkt_time - last_pkt_time) / self.replay_speed
                if 0 < dt < 0.1: # Cap sleep to avoid stalls
                    await asyncio.sleep(dt)
            last_pkt_time = pkt_time

            fwd_key = (src_ip, dst_ip, sport, dport, proto)
            rev_key = (dst_ip, src_ip, dport, sport, proto)

            if rev_key in active_flows:
                key = rev_key
                is_fwd = False
            else:
                key = fwd_key
                is_fwd = True

            if key not in active_flows:
                active_flows[key] = {
                    "times": [], "lengths": [], "payloads": b"",
                    "syn_count": 0, "rst_count": 0, "fin_count": 0,
                    "fwd_pkts": 0, "bwd_pkts": 0, "fwd_bytes": 0, "bwd_bytes": 0,
                    "src_ip": src_ip if is_fwd else dst_ip,
                    "dst_ip": dst_ip if is_fwd else src_ip,
                    "src_port": sport if is_fwd else dport,
                    "dst_port": dport if is_fwd else sport,
                    "protocol": proto,
                    "last_seen": pkt_time,
                    "dns_query": dns_qname
                }

            fl = active_flows[key]
            fl["times"].append(pkt_time)
            fl["lengths"].append(pkt_len)
            fl["last_seen"] = pkt_time
            if is_fwd:
                fl["fwd_pkts"] += 1
                fl["fwd_bytes"] += pkt_len
            else:
                fl["bwd_pkts"] += 1
                fl["bwd_bytes"] += pkt_len

            if is_syn: fl["syn_count"] += 1
            if is_rst: fl["rst_count"] += 1
            if is_fin: fl["fin_count"] += 1
            if len(fl["payloads"]) < 2048 and payload_b:
                fl["payloads"] += payload_b[:256]
            if dns_qname and not fl["dns_query"]:
                fl["dns_query"] = dns_qname

            # Check and flush timed-out flows
            stale_keys = [k for k, v in active_flows.items() if (pkt_time - v["last_seen"]) > self.flow_timeout_sec]
            for sk in stale_keys:
                alert = self._process_single_flow(active_flows[sk])
                del active_flows[sk]
                if alert:
                    yield alert

        # Flush remaining flows at end of PCAP
        for fl in list(active_flows.values()):
            alert = self._process_single_flow(fl)
            if alert:
                yield alert

        self.end_time = time.perf_counter()
        self.is_running = False

    def _process_single_flow(self, fl: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        n_pkts = len(fl["times"])
        if n_pkts < 2:
            return None

        t0 = time.perf_counter()
        self.flows_processed += 1

        times = np.array(fl["times"])
        lengths = np.array(fl["lengths"])
        iats = np.diff(times)
        dur = float(times[-1] - times[0])
        tot_bytes = int(np.sum(lengths))

        iat_m = float(np.mean(iats)) if len(iats) > 0 else 0.0
        iat_s = float(np.std(iats)) if len(iats) > 0 else 0.0
        pkt_m = float(np.mean(lengths))
        pkt_s = float(np.std(lengths)) if len(lengths) > 1 else 0.0
        
        # Calculate entropy
        counts = defaultdict(int)
        for b in fl["payloads"]: counts[b] += 1
        plen = len(fl["payloads"])
        entropy = float(-sum((c/plen) * math.log2(c/plen) for c in counts.values())) if plen > 0 else 0.0

        syn_r = float(fl["syn_count"] / n_pkts)
        rst_r = float(fl["rst_count"] / n_pkts)
        fin_r = float(fl["fin_count"] / n_pkts)

        flow_dict = {
            "source_ip": fl["src_ip"],
            "destination_ip": fl["dst_ip"],
            "source_port": fl["src_port"],
            "destination_port": fl["dst_port"],
            "protocol": fl["protocol"],
            "iat_mean": iat_m,
            "iat_std": iat_s,
            "pkt_len_mean": pkt_m,
            "pkt_len_std": pkt_s,
            "payload_entropy": entropy,
            "syn_ratio": syn_r,
            "tcp_rst_ratio": rst_r,
            "tcp_fin_ratio": fin_r,
            "duration": dur,
            "packet_count": n_pkts,
            "byte_count": tot_bytes,
            "forward_bytes": fl["fwd_bytes"],
            "backward_bytes": fl["bwd_bytes"],
            "forward_pkts": fl["fwd_pkts"],
            "backward_pkts": fl["bwd_pkts"],
            "dns_query": fl.get("dns_query")
        }

        # 1. Supervised Model inference
        prediction = "Benign"
        confidence = 0.50
        if self.model and self.scaler:
            import torch
            v1_raw = np.array([[iat_m, iat_s, pkt_m, pkt_s, entropy, syn_r]], dtype=np.float32)
            v1_scaled = self.scaler.transform(v1_raw)
            with torch.no_grad():
                logits = self.model(torch.tensor(v1_scaled, dtype=torch.float32))
                probs = torch.softmax(logits, dim=1).numpy()[0]
                pidx = int(np.argmax(probs))
                confidence = float(probs[pidx])
                prediction = self.class_names[pidx]

        # 2. Anomaly Detection
        ano_score = 0.0
        is_ano = False
        if self.anomaly_detector:
            ano_res = self.anomaly_detector.score(flow_dict)
            ano_score = ano_res["anomaly_score"]
            is_ano = ano_res["is_anomaly"]

        # 3. Behaviour Analytics
        behav_score = 0.0
        behav_type = "Benign"
        behav_ev = []
        if self.behaviour_engine:
            b_res = self.behaviour_engine.analyse(flow_dict)
            behav_score = b_res.behaviour_score
            behav_type = b_res.behaviour_type
            behav_ev = b_res.evidence

        # 4. Specialized Detectors
        spec_results = self.specialized_registry.evaluate_all(flow_dict)
        spec_evidence = []
        for s in spec_results:
            if s.is_detected:
                spec_evidence.extend(s.evidence)

        # 5. Risk Fusion
        fusion = self.fusion_engine.fuse(
            supervised_prediction=prediction,
            supervised_confidence=confidence,
            anomaly_score=ano_score,
            behaviour_score=behav_score,
            behaviour_type=behav_type,
            behaviour_evidence=behav_ev
        )

        t1 = time.perf_counter()
        lat_ms = (t1 - t0) * 1000.0
        self.latencies_ms.append(lat_ms)

        # Build Standardized Alert
        alert_id = str(uuid.uuid4())
        flow_id = f"{fl['src_ip']}:{fl['src_port']}->{fl['dst_ip']}:{fl['dst_port']}[{fl['protocol']}]"
        
        # Combine evidence items into structured format
        evidence_items = []
        for item in spec_evidence:
            evidence_items.append({"feature": item.feature, "observed_value": item.observed_value, "interpretation": item.interpretation})
        for ev_str in fusion.evidence:
            evidence_items.append({"feature": "fusion_signal", "observed_value": ev_str, "interpretation": ev_str})

        threat_cls = fusion.dominant_threat if fusion.dominant_threat != "Benign" else prediction
        detection_sources = ["supervised_classifier"]
        if is_ano: detection_sources.append("anomaly_detector")
        if behav_type != "Benign": detection_sources.append("behaviour_analytics")
        if any(s.is_detected for s in spec_results): detection_sources.append("specialized_detectors")

        alert_doc = {
            "alert_id": alert_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "flow_id": flow_id,
            "src_ip": fl["src_ip"],
            "dst_ip": fl["dst_ip"],
            "src_port": fl["src_port"],
            "dst_port": fl["dst_port"],
            "protocol": fl["protocol"],
            "source_ip": fl["src_ip"],
            "destination_ip": fl["dst_ip"],
            "source_port": fl["src_port"],
            "destination_port": fl["dst_port"],
            "prediction": prediction,
            "confidence": round(confidence, 4),
            "threat_class": threat_cls,
            "dominant_threat": threat_cls,
            "risk_score": fusion.final_risk_score,
            "final_risk_score": fusion.final_risk_score,
            "severity": fusion.severity,
            "anomaly_score": ano_score,
            "is_anomaly": is_ano,
            "behaviour_score": behav_score,
            "behaviour_type": behav_type,
            "detection_sources": detection_sources,
            "evidence": evidence_items,
            "explanation": fusion.explanation,
            "model_version": "DiodeThreatNet-v1.0-baseline",
            "feature_schema_version": "v1.0-baseline",
            "analysis_mode": "streaming_pcap_replay",
            "one_way_safe": True,
            "inference_latency_ms": round(lat_ms, 3),
            "features": flow_dict
        }

        # Track correlation
        self.correlation_engine.ingest_alert(alert_doc)
        self.alerts_emitted += 1

        return alert_doc
