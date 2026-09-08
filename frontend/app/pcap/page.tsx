'use client';

import { useState, useRef, useCallback } from 'react';
import { API } from '../lib/api';
import type { Alert } from '../lib/types';
import { TopBar } from '../components/TopBar';
import { SeverityBadge } from '../components/SeverityBadge';
import { AlertDrawer } from '../components/AlertDrawer';
import { Upload, ArrowDown } from 'lucide-react';

type Stage = 'idle' | 'uploading' | 'done' | 'error';

const PIPELINE = [
  { label: 'PCAP Input',           sub: 'Upload .pcap file' },
  { label: 'Flow Extraction',      sub: '5-tuple grouping' },
  { label: 'Feature Engineering',  sub: '21 per-flow features' },
  { label: 'Detection',            sub: 'Classifier + Anomaly + Behaviour' },
  { label: 'Risk Fusion',          sub: '50/25/25 weights' },
  { label: 'Alerts',               sub: 'Severity-ranked results' },
];

const THREAT_COLORS: Record<string, string> = {
  'SYN/UDP Flood': '#ef4444', 'DNS Tunneling': '#06b6d4',
  'C2 Beaconing': '#f97316', 'Anomaly': '#f59e0b', 'Benign': '#22c55e',
};

function proto(n: number) {
  return n === 6 ? 'TCP' : n === 17 ? 'UDP' : n === 1 ? 'ICMP' : String(n);
}

export default function PcapAnalysis() {
  const [stage,    setStage]    = useState<Stage>('idle');
  const [results,  setResults]  = useState<Alert[]>([]);
  const [message,  setMessage]  = useState('');
  const [selected, setSelected] = useState<Alert | null>(null);
  const [fileName, setFileName] = useState('');
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const processFile = useCallback(async (file: File) => {
    if (!file.name.toLowerCase().endsWith('.pcap')) {
      setMessage('Only .pcap files are supported.');
      setStage('error');
      return;
    }
    setFileName(file.name);
    setStage('uploading');
    setMessage(`Processing ${file.name}…`);
    setResults([]);
    try {
      const data = await API.analyzePcap(file);
      setResults(data.results ?? []);
      setMessage(data.message);
      setStage('done');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      setMessage(`Error: ${msg}`);
      setStage('error');
    }
  }, []);

  const onFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) processFile(f);
  };

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files?.[0];
    if (f) processFile(f);
  };

  const sorted = [...results].sort((a, b) => b.final_risk_score - a.final_risk_score);
  const threats = sorted.filter((a) => a.dominant_threat !== 'Benign');
  const benign  = sorted.filter((a) => a.dominant_threat === 'Benign');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>
      <TopBar title="PCAP Analysis" subtitle="Upload a packet capture for offline flow analysis · Not live capture" />

      <div style={{ flex: 1, padding: 24, display: 'flex', gap: 20 }}>
        {/* Left: upload + pipeline */}
        <div style={{ width: 280, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Drop zone */}
          <div
            onClick={() => inputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            className="gg-card"
            style={{
              padding: 24, textAlign: 'center', cursor: 'pointer',
              border: `1px solid ${dragging ? 'var(--gg-cyan)' : 'var(--gg-border)'}`,
              background: dragging ? 'rgba(6,182,212,0.05)' : 'var(--gg-surface)',
              transition: 'all 0.15s ease',
            }}
          >
            <Upload size={28} color={dragging ? 'var(--gg-cyan)' : 'var(--gg-muted)'} style={{ margin: '0 auto 12px' }} />
            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--gg-text-2)', marginBottom: 6 }}>
              {fileName || 'Drop PCAP here'}
            </p>
            <p style={{ fontSize: 11, color: 'var(--gg-muted)' }}>or click to browse</p>
            <p style={{ fontSize: 10, color: '#374151', marginTop: 8 }}>.pcap files only</p>
            <input ref={inputRef} type="file" accept=".pcap" style={{ display: 'none' }} onChange={onFileChange} />
          </div>

          {/* Status */}
          {stage !== 'idle' && (
            <div className="gg-card" style={{
              padding: 14,
              borderColor: stage === 'error' ? 'rgba(239,68,68,0.3)' : stage === 'done' ? 'rgba(34,197,94,0.3)' : 'var(--gg-border)',
            }}>
              {stage === 'uploading' && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{
                    width: 12, height: 12, border: '2px solid var(--gg-border-2)',
                    borderTop: '2px solid var(--gg-cyan)', borderRadius: '50%',
                    animation: 'spin 0.8s linear infinite', flexShrink: 0,
                  }} />
                  <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
                  <span style={{ fontSize: 12, color: 'var(--gg-text-2)' }}>{message}</span>
                </div>
              )}
              {stage === 'done' && <p style={{ fontSize: 12, color: 'var(--gg-green)' }}>✓ {message}</p>}
              {stage === 'error' && <p style={{ fontSize: 12, color: 'var(--gg-red)' }}>✗ {message}</p>}
            </div>
          )}

          {/* Pipeline visualization */}
          <div className="gg-card" style={{ padding: 16 }}>
            <p className="gg-label" style={{ marginBottom: 12 }}>Analysis Pipeline</p>
            {PIPELINE.map((step, i) => (
              <div key={step.label}>
                <div style={{
                  padding: '8px 10px',
                  border: '1px solid var(--gg-border)',
                  borderRadius: 6,
                  background: stage === 'done' ? 'rgba(34,197,94,0.04)' : 'transparent',
                  borderColor: stage === 'done' ? 'rgba(34,197,94,0.2)' : 'var(--gg-border)',
                }}>
                  <p style={{ fontSize: 11, fontWeight: 600, color: stage === 'done' ? 'var(--gg-green)' : 'var(--gg-text-2)' }}>
                    {stage === 'done' && '✓ '}{step.label}
                  </p>
                  <p style={{ fontSize: 10, color: 'var(--gg-muted)' }}>{step.sub}</p>
                </div>
                {i < PIPELINE.length - 1 && (
                  <div style={{ display: 'flex', justifyContent: 'center', padding: '3px 0' }}>
                    <ArrowDown size={12} color="var(--gg-muted)" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Right: results */}
        <div style={{ flex: 1, minWidth: 0 }}>
          {stage === 'idle' && (
            <div className="gg-card" style={{ padding: 40, textAlign: 'center', height: '100%',
              display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
              <Upload size={40} color="var(--gg-muted)" style={{ opacity: 0.3 }} />
              <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--gg-text-2)' }}>Upload a PCAP File</p>
              <p style={{ fontSize: 12, color: 'var(--gg-muted)', maxWidth: 320 }}>
                Upload a .pcap file to extract flows, compute features, and run the full detection pipeline.
                This is offline PCAP analysis — not live packet capture.
              </p>
              <p style={{ fontSize: 10, color: '#374151' }}>
                A sample file (traffic_sample.pcap) is available in the backend/ directory.
              </p>
            </div>
          )}

          {stage === 'done' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Summary cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                {[
                  { label: 'Total Flows', value: results.length, color: 'var(--gg-text)' },
                  { label: 'Threats', value: threats.length, color: threats.length > 0 ? 'var(--gg-red)' : 'var(--gg-green)' },
                  { label: 'Benign', value: benign.length, color: 'var(--gg-green)' },
                ].map((s) => (
                  <div key={s.label} className="gg-card" style={{ padding: 16 }}>
                    <p className="gg-label" style={{ marginBottom: 6 }}>{s.label}</p>
                    <p style={{ fontSize: 24, fontWeight: 700, color: s.color }}>{s.value}</p>
                  </div>
                ))}
              </div>

              {/* Alert table */}
              <div className="gg-card" style={{ padding: 20 }}>
                <p className="gg-label" style={{ marginBottom: 14 }}>Flow Analysis Results</p>
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '1px solid var(--gg-border)' }}>
                        {['Source → Dest', 'Proto', 'Threat', 'Classifier', 'Risk', 'Severity'].map((h) => (
                          <th key={h} style={{ padding: '0 10px 10px 0', fontSize: 10, fontWeight: 600,
                            letterSpacing: '0.08em', textTransform: 'uppercase' as const,
                            color: 'var(--gg-muted)', textAlign: 'left' as const }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {sorted.map((a, i) => (
                        <tr
                          key={a.alert_id ?? i}
                          onClick={() => setSelected(a)}
                          style={{ borderBottom: '1px solid rgba(31,41,55,0.4)', cursor: 'pointer' }}
                          onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--gg-surface-2)')}
                          onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                        >
                          <td style={{ padding: '8px 10px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>
                            {a.source_ip} → {a.destination_ip}
                          </td>
                          <td style={{ padding: '8px 10px 8px 0', fontSize: 11, color: 'var(--gg-muted)' }}>{proto(a.protocol)}</td>
                          <td style={{ padding: '8px 10px 8px 0' }}>
                            <span style={{ fontSize: 12, fontWeight: 600, color: THREAT_COLORS[a.dominant_threat] ?? 'var(--gg-text-2)' }}>
                              {a.dominant_threat}
                            </span>
                          </td>
                          <td style={{ padding: '8px 10px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>
                            {(a.confidence * 100).toFixed(0)}%
                          </td>
                          <td style={{ padding: '8px 10px 8px 0', fontSize: 11, fontFamily: 'var(--font-mono)',
                            color: a.final_risk_score > 0.65 ? 'var(--gg-red)' : a.final_risk_score > 0.4 ? 'var(--gg-amber)' : 'var(--gg-green)' }}>
                            {(a.final_risk_score * 100).toFixed(0)}
                          </td>
                          <td style={{ padding: '8px 0' }}><SeverityBadge severity={a.severity} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {stage === 'error' && (
            <div className="gg-card" style={{
              padding: 32, textAlign: 'center',
              border: '1px solid rgba(239,68,68,0.3)',
            }}>
              <p style={{ fontSize: 14, color: 'var(--gg-red)', fontWeight: 600, marginBottom: 8 }}>PCAP Analysis Failed</p>
              <p style={{ fontSize: 12, color: 'var(--gg-muted)' }}>{message}</p>
              <p style={{ fontSize: 11, color: '#374151', marginTop: 12 }}>
                Ensure the backend is running and scapy is installed (pip install scapy).
              </p>
            </div>
          )}
        </div>
      </div>

      {selected && <AlertDrawer alert={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
