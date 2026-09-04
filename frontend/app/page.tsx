'use client';

/**
 * SIH 26145 — Passive Cyber Intelligence Dashboard
 *
 * All metrics are derived from real API responses.
 * No Math.random() or hardcoded operational values.
 * Random values removed per Phase 9 requirements.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowDown, BarChart3, ChevronDown,
  ChevronUp, Cpu, Info, Radio, Server, ShieldAlert, X, Zap,
} from 'lucide-react';
import {
  AreaChart, Area, Cell, PieChart, Pie,
  ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';

// ── Types ──────────────────────────────────────────────────────────────────

interface Alert {
  alert_id:            string;
  timestamp:           string;
  model_version?:      string;
  source_ip:           string;
  destination_ip:      string;
  source_port:         number;
  destination_port:    number;
  protocol:            number;
  prediction:          string;
  confidence:          number;
  anomaly_score:       number;
  is_anomaly:          boolean;
  behaviour_score:     number;
  behaviour_type:      string;
  final_risk_score:    number;
  severity:            string;
  dominant_threat:     string;
  evidence:            string[];
  explanation:         string;
  inference_latency_ms?: number;
  features?:           Record<string, number>;
}

interface Stats {
  flows_processed:                number;
  threats_detected:               number;
  high_risk_alerts:               number;
  anomaly_count:                  number;
  average_inference_latency_ms:   number | null;
  storage_backend:                string;
  model_version:                  string;
  started_at:                     string;
}

interface TrendPoint {
  time:     string;
  threats:  number;
  benign:   number;
}

// ── Constants ──────────────────────────────────────────────────────────────

const API_BASE = 'http://127.0.0.1:8000';

const THREAT_COLORS: Record<string, string> = {
  'SYN/UDP Flood':  '#f43f5e',
  'DNS Tunneling':  '#38bdf8',
  'C2 Beaconing':   '#a78bfa',
  'Anomaly':        '#f59e0b',
  'Benign':         '#10b981',
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

function severityClass(sev: string): string {
  switch (sev) {
    case 'CRITICAL': return 'severity-critical';
    case 'HIGH':     return 'severity-high';
    case 'MEDIUM':   return 'severity-medium';
    default:         return 'severity-low';
  }
}

function protocolName(proto: number): string {
  if (proto === 6)  return 'TCP';
  if (proto === 17) return 'UDP';
  if (proto === 1)  return 'ICMP';
  return proto ? String(proto) : '—';
}

function fmtTime(iso: string): string {
  try {
    return new Date(iso).toLocaleTimeString('en-GB', { hour12: false });
  } catch {
    return iso;
  }
}

function fmtPct(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

// ── Tooltip styles ─────────────────────────────────────────────────────────

const tooltipStyle = {
  backgroundColor: '#0f172a',
  borderColor:     '#334155',
  color:           '#e2e8f0',
  fontSize:        '11px',
  fontFamily:      'var(--font-geist-mono, monospace)',
};

// ── Sub-components ─────────────────────────────────────────────────────────

function KpiCard({
  label, value, unit, icon: Icon, color = 'text-emerald-400', note,
}: {
  label: string; value: string | number | null; unit?: string;
  icon: React.ElementType; color?: string; note?: string;
}) {
  return (
    <div className="p-5 bg-slate-900 border border-slate-800 rounded-xl flex flex-col gap-2 hover:border-slate-700 transition-colors">
      <div className="flex justify-between items-center text-slate-500 text-[10px] uppercase tracking-widest">
        <span>{label}</span>
        <Icon className={`w-4 h-4 ${color}`} />
      </div>
      <div className="text-2xl font-bold text-slate-100 flex items-end gap-2">
        {value !== null ? value : <span className="text-slate-600 text-base">N/A</span>}
        {value !== null && unit && (
          <span className="text-xs font-normal text-slate-500 mb-0.5">{unit}</span>
        )}
      </div>
      {note && <p className="text-[10px] text-slate-600">{note}</p>}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold border ${severityClass(severity)}`}>
      {severity}
    </span>
  );
}

// ── Alert Detail Modal ─────────────────────────────────────────────────────

function AlertModal({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const riskPct = Math.round(alert.final_risk_score * 100);

  // Colour the risk bar
  const riskBarColor =
    alert.severity === 'CRITICAL' ? 'bg-rose-500' :
    alert.severity === 'HIGH'     ? 'bg-orange-500' :
    alert.severity === 'MEDIUM'   ? 'bg-amber-500'  : 'bg-emerald-500';

  return (
    <div className="modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="flex justify-between items-start mb-6">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              <h2 className="text-lg font-bold text-slate-100">
                {alert.dominant_threat}
              </h2>
              <SeverityBadge severity={alert.severity} />
            </div>
            <p className="text-[11px] text-slate-500">
              Alert ID: {alert.alert_id} · {fmtTime(alert.timestamp)}
              {alert.model_version && ` · ${alert.model_version}`}
            </p>
          </div>
          <button
            id="modal-close-btn"
            onClick={onClose}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            aria-label="Close alert detail"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Risk score bar */}
        <div className="mb-6">
          <div className="flex justify-between text-[11px] text-slate-400 mb-1">
            <span>FUSED RISK SCORE</span>
            <span className="font-bold text-slate-200">{riskPct} / 100</span>
          </div>
          <div className="h-2 rounded-full bg-slate-800">
            <div
              className={`h-2 rounded-full transition-all ${riskBarColor}`}
              style={{ width: `${riskPct}%` }}
            />
          </div>
        </div>

        {/* Detection scores */}
        <div className="grid grid-cols-3 gap-3 mb-6">
          {[
            { label: 'Classifier',  value: fmtPct(alert.confidence),     sub: alert.prediction },
            { label: 'Anomaly',     value: fmtPct(alert.anomaly_score),   sub: alert.is_anomaly ? 'FLAGGED' : 'normal' },
            { label: 'Behaviour',   value: fmtPct(alert.behaviour_score), sub: alert.behaviour_type || '—' },
          ].map(({ label, value, sub }) => (
            <div key={label} className="bg-slate-800/60 rounded-lg p-3 text-center">
              <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-1">{label}</p>
              <p className="text-xl font-bold text-slate-100">{value}</p>
              <p className="text-[10px] text-slate-400 mt-0.5 truncate">{sub}</p>
            </div>
          ))}
        </div>

        {/* Flow identity */}
        <div className="mb-5 bg-slate-800/40 rounded-lg p-4 text-[11px] font-mono">
          <p className="text-slate-500 uppercase tracking-widest text-[10px] mb-2">Flow Metadata</p>
          <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-slate-300">
            <span className="text-slate-500">Source</span>
            <span>{alert.source_ip}:{alert.source_port}</span>
            <span className="text-slate-500">Destination</span>
            <span>{alert.destination_ip}:{alert.destination_port}</span>
            <span className="text-slate-500">Protocol</span>
            <span>{protocolName(alert.protocol)}</span>
            {alert.inference_latency_ms !== undefined && (
              <>
                <span className="text-slate-500">Inference</span>
                <span>{alert.inference_latency_ms.toFixed(2)} ms</span>
              </>
            )}
          </div>
        </div>

        {/* Evidence */}
        {alert.evidence && alert.evidence.length > 0 && (
          <div className="mb-5">
            <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-2">Detection Evidence</p>
            <ul className="space-y-1.5">
              {alert.evidence.map((ev, i) => (
                <li key={i} className="flex gap-2 text-[11px] text-slate-300">
                  <span className="text-emerald-400 mt-0.5 flex-shrink-0">•</span>
                  <span>{ev}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Explanation */}
        {alert.explanation && (
          <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4">
            <p className="text-[10px] text-slate-500 uppercase tracking-widest mb-2 flex items-center gap-1">
              <Info className="w-3 h-3" /> Analyst Explanation
            </p>
            <p className="text-[12px] text-slate-300 leading-relaxed">{alert.explanation}</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── One-Way Data Path Card ─────────────────────────────────────────────────

function DataPathCard() {
  const nodes = [
    { label: 'Protected Network', color: 'border-cyan-700 text-cyan-400 bg-cyan-950/30' },
    { label: 'One-Way Ingestion', color: 'border-emerald-700 text-emerald-400 bg-emerald-950/30' },
    { label: 'Analytics Enclave', color: 'border-violet-700 text-violet-400 bg-violet-950/30' },
    { label: 'SOC Dashboard',     color: 'border-amber-700  text-amber-400  bg-amber-950/30'  },
  ];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <h3 className="text-[10px] text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2">
        <ArrowDown className="w-3 h-3 text-emerald-400" />
        Data Path (Software Prototype Indicator)
      </h3>

      <div className="flex flex-col items-center gap-1">
        {nodes.map((node, i) => (
          <React.Fragment key={node.label}>
            <div className={`diode-path-node border w-full text-center ${node.color}`}>
              {node.label}
            </div>
            {i < nodes.length - 1 && (
              <ArrowDown className="w-4 h-4 text-slate-600 animate-flow-arrow" />
            )}
          </React.Fragment>
        ))}
      </div>

      <div className="mt-4 pt-3 border-t border-slate-800">
        <div className="flex justify-between text-[10px]">
          <span className="text-slate-500">Return Traffic</span>
          <span className="text-emerald-400 font-bold">0 packets</span>
        </div>
        <p className="text-[9px] text-slate-700 mt-1 leading-relaxed">
          Software prototype indicator only. Physical one-way isolation
          requires dedicated hardware (data diode).
        </p>
      </div>
    </div>
  );
}

// ── Demo Mode Panel ────────────────────────────────────────────────────────

function DemoPanel({ onRefresh }: { onRefresh: () => void }) {
  const [running, setRunning]   = useState(false);
  const [status, setStatus]     = useState('');
  const [mode, setMode]         = useState('mixed');
  const [count, setCount]       = useState(10);

  const modes = [
    { value: 'mixed',     label: 'Mixed',        color: 'bg-slate-700' },
    { value: 'normal',    label: 'Normal',        color: 'bg-emerald-900' },
    { value: 'syn_flood', label: 'SYN Flood',     color: 'bg-rose-900' },
    { value: 'dns_tunnel',label: 'DNS Tunnel',    color: 'bg-cyan-900' },
    { value: 'c2_beacon', label: 'C2 Beacon',     color: 'bg-violet-900' },
  ];

  /**
   * Calls the backend API directly to simulate flows.
   * The simulator profiles are replicated here so the dashboard
   * can trigger them without a separate CLI process.
   */
  const runSimulation = useCallback(async () => {
    if (running) return;
    setRunning(true);
    setStatus(`Injecting ${count} ${mode} flows…`);

    const profiles: Record<string, object[]> = {
      normal: [
        { source_ip:'10.0.1.10', destination_ip:'10.0.0.1', source_port:54321, destination_port:80, protocol:6,
          iat_mean:0.05, iat_std:0.02, pkt_len_mean:600, pkt_len_std:100, payload_entropy:5.0, syn_ratio:0.03,
          tcp_rst_ratio:0.01, tcp_fin_ratio:0.05, duration:2.0, packet_count:40, byte_count:24000,
          forward_pkts:20, backward_pkts:20, forward_bytes:12000, backward_bytes:12000 },
      ],
      syn_flood: [
        { source_ip:'10.0.4.182', destination_ip:'10.0.0.1', source_port:12345, destination_port:80, protocol:6,
          iat_mean:0.0003, iat_std:0.00005, pkt_len_mean:64, pkt_len_std:2, payload_entropy:0.15, syn_ratio:0.99,
          tcp_rst_ratio:0.0, tcp_fin_ratio:0.0, duration:0.5, packet_count:800, byte_count:51200,
          forward_pkts:800, backward_pkts:0, forward_bytes:51200, backward_bytes:0 },
      ],
      dns_tunnel: [
        { source_ip:'192.168.10.45', destination_ip:'8.8.8.8', source_port:45678, destination_port:53, protocol:17,
          iat_mean:0.08, iat_std:0.02, pkt_len_mean:190, pkt_len_std:35, payload_entropy:7.9, syn_ratio:0.0,
          tcp_rst_ratio:0.0, tcp_fin_ratio:0.0, duration:5.0, packet_count:60, byte_count:11400,
          forward_pkts:30, backward_pkts:30, forward_bytes:5700, backward_bytes:5700 },
      ],
      c2_beacon: [
        { source_ip:'172.16.0.88', destination_ip:'91.195.240.117', source_port:55123, destination_port:443, protocol:6,
          iat_mean:2.001, iat_std:0.0001, pkt_len_mean:125, pkt_len_std:5, payload_entropy:4.1, syn_ratio:0.0,
          tcp_rst_ratio:0.01, tcp_fin_ratio:0.02, duration:120.0, packet_count:60, byte_count:7500,
          forward_pkts:30, backward_pkts:30, forward_bytes:3750, backward_bytes:3750 },
      ],
    };

    const cycle =
      mode === 'mixed'
        ? ['syn_flood', 'dns_tunnel', 'c2_beacon', 'normal']
        : [mode];

    let ok = 0;
    for (let i = 0; i < count; i++) {
      const profileKey = cycle[i % cycle.length];
      const template   = profiles[profileKey]?.[0];
      if (!template) continue;

      const payload = { ...template };

      try {
        const res = await fetch(`${API_BASE}/api/v1/analyze-flow`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (res.ok) ok++;
        setStatus(`Injected ${i + 1}/${count} flows (${ok} OK)…`);
      } catch {
        setStatus(`Connection error — is the backend running?`);
        break;
      }

      await new Promise((r) => setTimeout(r, 300));
    }

    setStatus(`Done — ${ok}/${count} flows submitted.`);
    setRunning(false);
    onRefresh();
  }, [running, mode, count, onRefresh]);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <h3 className="text-[10px] text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2">
        <Zap className="w-3 h-3 text-amber-400" />
        Demo Mode — Traffic Injection
      </h3>

      <div className="flex flex-wrap gap-1.5 mb-3">
        {modes.map((m) => (
          <button
            key={m.value}
            id={`demo-mode-${m.value}`}
            onClick={() => setMode(m.value)}
            className={`px-3 py-1 rounded text-[11px] font-semibold border transition-all
              ${mode === m.value
                ? 'border-emerald-500 text-emerald-400 bg-emerald-950/40'
                : 'border-slate-700 text-slate-400 hover:border-slate-500'}`}
          >
            {m.label}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-3 mb-4">
        <label className="text-[10px] text-slate-500 uppercase tracking-widest">
          Count
        </label>
        {[5, 10, 20, 50].map((n) => (
          <button
            key={n}
            id={`demo-count-${n}`}
            onClick={() => setCount(n)}
            className={`px-2 py-0.5 rounded text-[11px] border transition-all
              ${count === n
                ? 'border-cyan-500 text-cyan-400 bg-cyan-950/30'
                : 'border-slate-700 text-slate-500 hover:border-slate-500'}`}
          >
            {n}
          </button>
        ))}
      </div>

      <button
        id="demo-inject-btn"
        onClick={runSimulation}
        disabled={running}
        className={`w-full py-2 rounded-lg text-sm font-bold border transition-all
          ${running
            ? 'border-slate-700 text-slate-600 cursor-not-allowed'
            : 'border-emerald-600 text-emerald-400 hover:bg-emerald-950/30'}`}
      >
        {running ? '⟳ Running…' : '▶ Inject Flows'}
      </button>

      {status && (
        <p className="mt-2 text-[10px] text-slate-500 font-mono">{status}</p>
      )}
    </div>
  );
}

// ── Main Dashboard ─────────────────────────────────────────────────────────

export default function Dashboard() {
  const [alerts, setAlerts]     = useState<Alert[]>([]);
  const [stats, setStats]       = useState<Stats | null>(null);
  const [trend, setTrend]       = useState<TrendPoint[]>([]);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [backendOk, setBackendOk] = useState<boolean | null>(null);
  const [expanded, setExpanded] = useState(true);
  const trendRef = useRef<TrendPoint[]>([]);

  // ── Fetch stats ────────────────────────────────────────────────────────
  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/stats`);
      if (!res.ok) { setBackendOk(false); return; }
      const data: Stats = await res.json();
      setStats(data);
      setBackendOk(true);
    } catch {
      setBackendOk(false);
    }
  }, []);

  // ── Fetch alerts ───────────────────────────────────────────────────────
  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/alerts?limit=100`);
      if (!res.ok) return;
      const data: Alert[] = await res.json();
      if (!Array.isArray(data)) return;
      setAlerts(data);

      // Build trend: bucket alerts into 30-second windows
      const now     = Date.now();
      const windows = 12; // last 6 minutes in 30s windows
      const pts: TrendPoint[] = [];
      for (let w = windows - 1; w >= 0; w--) {
        const windowEnd   = now - w * 30_000;
        const windowStart = windowEnd - 30_000;
        const label       = new Date(windowEnd).toLocaleTimeString('en-GB', { hour12: false }).slice(0, 5);
        const threats     = data.filter(a => {
          const t = new Date(a.timestamp).getTime();
          return t >= windowStart && t < windowEnd && a.dominant_threat !== 'Benign';
        }).length;
        pts.push({ time: label, threats, benign: 0 });
      }
      trendRef.current = pts;
      setTrend([...pts]);
    } catch {
      // Silently ignore polling errors
    }
  }, []);

  const refresh = useCallback(() => {
    fetchStats();
    fetchAlerts();
  }, [fetchStats, fetchAlerts]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 3000);
    return () => clearInterval(id);
  }, [refresh]);

  // ── Derived data ───────────────────────────────────────────────────────

  // Threat distribution from real alert data
  const threatCounts: Record<string, number> = {};
  for (const a of alerts) {
    const key = a.dominant_threat || a.prediction || 'Unknown';
    threatCounts[key] = (threatCounts[key] || 0) + 1;
  }
  const pieData = Object.entries(threatCounts).map(([name, value]) => ({ name, value }));

  // Sort alerts by timestamp descending for display
  const sortedAlerts = [...alerts].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  // KPI values from real stats
  const flowsAnalysed  = stats?.flows_processed ?? null;
  const threatsDetected = stats?.threats_detected ?? null;
  const highRiskAlerts  = stats?.high_risk_alerts ?? null;
  const avgLatency      = stats?.average_inference_latency_ms
    ? `${stats.average_inference_latency_ms.toFixed(2)}`
    : null;

  // ── Render ─────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-4 md:p-6 lg:p-8">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <header className="flex flex-col md:flex-row justify-between items-start md:items-center border-b border-slate-800 pb-5 mb-6 gap-3">
        <div>
          <h1 className="text-xl md:text-2xl font-bold tracking-widest text-emerald-400 flex items-center gap-2 uppercase">
            <Radio className="w-5 h-5 animate-pulse-dot" />
            Passive Cyber Intelligence
          </h1>
          <p className="text-[11px] text-slate-500 mt-1 tracking-wider uppercase">
            Unidirectional Monitoring Enclave · PS 26145 · SIH 2026
          </p>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {/* Backend status */}
          <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold border uppercase tracking-wider
            ${backendOk === true  ? 'border-emerald-600 text-emerald-400 bg-emerald-950/30' :
              backendOk === false ? 'border-rose-700 text-rose-400 bg-rose-950/30' :
                                   'border-slate-700 text-slate-500 bg-slate-900'}`}>
            <span className={`h-1.5 w-1.5 rounded-full
              ${backendOk === true ? 'bg-emerald-400 animate-pulse-dot' :
                backendOk === false ? 'bg-rose-500' : 'bg-slate-500'}`} />
            {backendOk === true ? 'Analytics Active' : backendOk === false ? 'Backend Offline' : 'Connecting…'}
          </span>

          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-bold border border-cyan-700 text-cyan-400 bg-cyan-950/20 uppercase tracking-wider">
            <ArrowDown className="w-3 h-3" />
            One-Way Ingestion
          </span>

          {stats?.model_version && (
            <span className="hidden lg:inline text-[10px] text-slate-600 font-mono">
              {stats.model_version}
            </span>
          )}
        </div>
      </header>

      {/* ── KPI Cards ──────────────────────────────────────────────────── */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6" aria-label="Key performance indicators">
        <KpiCard
          label="Flows Analysed"
          value={flowsAnalysed}
          icon={Activity}
          color="text-emerald-400"
          note="Since last backend start"
        />
        <KpiCard
          label="Threats Detected"
          value={threatsDetected}
          icon={ShieldAlert}
          color="text-rose-400"
        />
        <KpiCard
          label="High-Risk Alerts"
          value={highRiskAlerts}
          icon={AlertTriangle}
          color="text-orange-400"
          note="HIGH + CRITICAL severity"
        />
        <KpiCard
          label="Avg Inference"
          value={avgLatency}
          unit={avgLatency ? 'ms' : undefined}
          icon={Cpu}
          color="text-cyan-400"
          note="Per-flow classifier + engines"
        />
      </section>

      {/* ── Charts Row ─────────────────────────────────────────────────── */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6" aria-label="Analytics charts">

        {/* Threat trend */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-[10px] text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2">
            <Activity className="w-3 h-3 text-rose-400" />
            Threat Detections — 6-Minute Rolling Window (30s buckets)
          </h3>
          {trend.length === 0 ? (
            <div className="h-40 flex items-center justify-center text-slate-600 text-sm">
              No threat data yet — run the simulator or analyse a PCAP
            </div>
          ) : (
            <div className="h-40">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trend}>
                  <defs>
                    <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%"  stopColor="#f43f5e" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#f43f5e" stopOpacity={0}   />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#475569" fontSize={10} tickLine={false} />
                  <YAxis stroke="#475569" fontSize={10} tickLine={false} allowDecimals={false} width={24} />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Area
                    type="monotone"
                    dataKey="threats"
                    stroke="#f43f5e"
                    strokeWidth={2}
                    fill="url(#threatGrad)"
                    dot={false}
                    name="Threats"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Threat distribution */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
          <h3 className="text-[10px] text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2">
            <BarChart3 className="w-3 h-3 text-violet-400" />
            Threat Distribution
          </h3>
          {pieData.length === 0 ? (
            <div className="h-40 flex items-center justify-center text-slate-600 text-sm">
              No alerts recorded
            </div>
          ) : (
            <div className="h-40">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%" cy="50%"
                    innerRadius={40} outerRadius={60}
                    dataKey="value"
                    paddingAngle={3}
                  >
                    {pieData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={THREAT_COLORS[entry.name] ?? '#64748b'}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={tooltipStyle}
                    formatter={(value, name) => [value ?? 0, name]}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
          {/* Legend */}
          <div className="mt-2 space-y-1">
            {pieData.slice(0, 5).map((entry) => (
              <div key={entry.name} className="flex items-center justify-between text-[10px]">
                <span className="flex items-center gap-1.5">
                  <span
                    className="w-2 h-2 rounded-full flex-shrink-0"
                    style={{ backgroundColor: THREAT_COLORS[entry.name] ?? '#64748b' }}
                  />
                  <span className="text-slate-400">{entry.name}</span>
                </span>
                <span className="text-slate-500">{entry.value}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── Bottom Row: Table + Side Panels ────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">

        {/* ── Passive Threat Stream ────────────────────────────────────── */}
        <div className="xl:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              Passive Threat Stream
            </h2>
            <button
              id="stream-collapse-btn"
              onClick={() => setExpanded((x) => !x)}
              className="text-slate-500 hover:text-slate-300 transition-colors"
              aria-label="Collapse threat stream"
            >
              {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>

          {expanded && (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs" aria-label="Threat stream table">
                <thead className="text-[10px] text-slate-600 uppercase tracking-widest border-b border-slate-800">
                  <tr>
                    <th className="pb-2 pr-3 font-medium">Time</th>
                    <th className="pb-2 pr-3 font-medium">Source → Dest</th>
                    <th className="pb-2 pr-3 font-medium">Proto</th>
                    <th className="pb-2 pr-3 font-medium">Classification</th>
                    <th className="pb-2 pr-3 font-medium">Risk</th>
                    <th className="pb-2 font-medium">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/40">
                  {sortedAlerts.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-600">
                        No alerts — inject traffic via Demo Mode or analyse a PCAP
                      </td>
                    </tr>
                  ) : (
                    sortedAlerts.slice(0, 50).map((alert) => (
                      <tr
                        key={alert.alert_id}
                        id={`alert-row-${alert.alert_id}`}
                        onClick={() => setSelected(alert)}
                        className="hover:bg-slate-800/40 cursor-pointer transition-colors animate-slide-in"
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => e.key === 'Enter' && setSelected(alert)}
                        aria-label={`Alert: ${alert.dominant_threat} from ${alert.source_ip}`}
                      >
                        <td className="py-2.5 pr-3 text-slate-500 font-mono whitespace-nowrap">
                          {fmtTime(alert.timestamp)}
                        </td>
                        <td className="py-2.5 pr-3 text-slate-300 font-mono whitespace-nowrap text-[11px]">
                          {alert.source_ip}
                          <span className="text-slate-600"> → </span>
                          {alert.destination_ip}
                        </td>
                        <td className="py-2.5 pr-3 text-slate-400">
                          {protocolName(alert.protocol)}
                        </td>
                        <td className="py-2.5 pr-3">
                          <span style={{ color: THREAT_COLORS[alert.dominant_threat] ?? '#94a3b8' }}
                                className="font-semibold">
                            {alert.dominant_threat}
                          </span>
                        </td>
                        <td className="py-2.5 pr-3">
                          <div className="flex items-center gap-1.5">
                            <div className="w-12 h-1.5 rounded-full bg-slate-800">
                              <div
                                className="h-1.5 rounded-full"
                                style={{
                                  width: `${Math.round(alert.final_risk_score * 100)}%`,
                                  backgroundColor: THREAT_COLORS[alert.dominant_threat] ?? '#64748b',
                                }}
                              />
                            </div>
                            <span className="text-slate-400 text-[10px] w-7 text-right">
                              {Math.round(alert.final_risk_score * 100)}
                            </span>
                          </div>
                        </td>
                        <td className="py-2.5">
                          <SeverityBadge severity={alert.severity} />
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* ── Side Panels ──────────────────────────────────────────────── */}
        <div className="flex flex-col gap-4">
          <DataPathCard />
          <DemoPanel onRefresh={refresh} />

          {/* Storage backend info */}
          {stats && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <p className="text-[10px] text-slate-600 uppercase tracking-widest mb-2 flex items-center gap-1.5">
                <Server className="w-3 h-3" /> System Info
              </p>
              <div className="space-y-1 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-slate-500">Storage</span>
                  <span className={`font-semibold ${stats.storage_backend === 'mongodb' ? 'text-emerald-400' : 'text-amber-400'}`}>
                    {stats.storage_backend === 'mongodb' ? 'MongoDB' : 'In-memory'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Anomalies</span>
                  <span className="text-slate-300">{stats.anomaly_count}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Started</span>
                  <span className="text-slate-400 font-mono text-[10px]">
                    {fmtTime(stats.started_at)}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ── Alert Detail Modal ─────────────────────────────────────────── */}
      {selected && (
        <AlertModal alert={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}