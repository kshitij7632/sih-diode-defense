'use client';

import { X, Info, ShieldAlert, Cpu, Activity, Database, CheckCircle2 } from 'lucide-react';
import type { Alert, StructuredEvidence } from '../lib/types';
import { SeverityBadge, RiskBar } from './SeverityBadge';

const THREAT_COLORS: Record<string, string> = {
  'SYN/UDP Flood': '#f87171',
  'DNS Tunneling': '#22d3ee',
  'C2 Beaconing':  '#fb923c',
  'Volumetric / Protocol DDoS': '#f87171',
  'Botnet C2 Beaconing': '#fb923c',
  'DGA Domains and DNS Tunnelling': '#22d3ee',
  'Reconnaissance / Port Scanning': '#a855f7',
  'Data Exfiltration': '#ec4899',
  'Malware in Encrypted Sessions': '#3b82f6',
  'Anomaly':       '#fbbf24',
  'Benign':        '#34d399',
};

function proto(n: number) {
  return n === 6 ? 'TCP' : n === 17 ? 'UDP' : n === 1 ? 'ICMP' : n ? String(n) : '—';
}
function pct(v: number) { return `${(v * 100).toFixed(1)}%`; }

export function AlertDrawer({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const threatColor = THREAT_COLORS[alert.dominant_threat] ?? 'var(--gg-text-2)';

  return (
    <div className="gg-modal-overlay" onClick={onClose} role="dialog" aria-modal="true">
      <div className="gg-modal-panel" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 640 }}>

        {/* ── Header ── */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
              <div style={{
                width: 32, height: 32,
                borderRadius: 'var(--gg-radius-sm)',
                background: `${threatColor}18`,
                border: `1px solid ${threatColor}44`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                boxShadow: `0 0 16px ${threatColor}28`,
              }}>
                <ShieldAlert size={18} color={threatColor} />
              </div>
              <h2 style={{ fontSize: 18, fontWeight: 800, color: 'var(--gg-text)', letterSpacing: '-0.01em' }}>
                {alert.dominant_threat || alert.threat_class}
              </h2>
              <SeverityBadge severity={alert.severity} />
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 11, color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)' }}>
                {alert.alert_id} · {new Date(alert.timestamp).toLocaleTimeString('en-GB', { hour12: false })}
              </span>
              {alert.analysis_mode && (
                <span style={{
                  fontSize: 10,
                  padding: '2px 8px',
                  borderRadius: 12,
                  background: 'rgba(6,182,212,0.1)',
                  border: '1px solid rgba(6,182,212,0.3)',
                  color: '#22d3ee',
                  textTransform: 'uppercase',
                  fontWeight: 600
                }}>
                  {alert.analysis_mode.replace('_', ' ')}
                </span>
              )}
              {alert.one_way_safe && (
                <span style={{
                  fontSize: 10,
                  padding: '2px 8px',
                  borderRadius: 12,
                  background: 'rgba(16,185,129,0.1)',
                  border: '1px solid rgba(16,185,129,0.3)',
                  color: '#34d399',
                  fontWeight: 600
                }}>
                  ✓ One-Way Safe
                </span>
              )}
            </div>
          </div>
          <button
            id="alert-drawer-close"
            onClick={onClose}
            style={{
              color: 'var(--gg-text-3)',
              cursor: 'pointer',
              background: 'rgba(255,255,255,0.05)',
              border: '1px solid var(--gg-border)',
              borderRadius: 6,
              padding: 6,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'all 0.15s ease',
            }}
            aria-label="Close alert detail"
          >
            <X size={16} />
          </button>
        </div>

        {/* ── Fused Risk Score ── */}
        <div style={{
          padding: 16,
          borderRadius: 'var(--gg-radius-sm)',
          background: 'rgba(255, 255, 255, 0.025)',
          border: '1px solid var(--gg-border)',
          marginBottom: 16,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span className="gg-label">Fused Multi-Signal Risk Score</span>
            <span style={{
              fontSize: 16,
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: threatColor,
              textShadow: `0 0 12px ${threatColor}66`,
            }}>
              {Math.round((alert.final_risk_score ?? alert.risk_score ?? 0) * 100)} / 100
            </span>
          </div>
          <RiskBar score={alert.final_risk_score ?? alert.risk_score ?? 0} severity={alert.severity} />
          <p style={{ fontSize: 10, color: 'var(--gg-muted)', marginTop: 8 }}>
            Ensemble: Supervised Classifier (50%) + Real-Benign Isolation Forest (25%) + Behaviour & Specialized Analytics (25%)
          </p>
        </div>

        {/* ── Detection Pillar Scores ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10, marginBottom: 16 }}>
          {[
            { label: 'Supervised ML', value: pct(alert.confidence), sub: alert.prediction, color: '#34d399' },
            { label: 'Anomaly Outlier', value: pct(alert.anomaly_score), sub: alert.is_anomaly ? 'FLAGGED (Real Benign)' : 'Normal', color: '#fbbf24' },
            { label: 'Behaviour & Pattern', value: pct(alert.behaviour_score), sub: alert.behaviour_type || '—', color: '#22d3ee' },
          ].map(({ label, value, sub, color }) => (
            <div key={label} style={{
              background: 'rgba(255, 255, 255, 0.03)',
              backdropFilter: 'blur(12px)',
              border: '1px solid var(--gg-border)',
              borderRadius: 'var(--gg-radius-sm)',
              padding: '12px 10px',
              textAlign: 'center',
            }}>
              <p className="gg-label" style={{ marginBottom: 4, fontSize: 10 }}>{label}</p>
              <p style={{
                fontSize: 18,
                fontWeight: 800,
                color: color,
                fontFamily: 'var(--font-mono)',
              }}>
                {value}
              </p>
              <p style={{ fontSize: 10, color: 'var(--gg-text-2)', marginTop: 2, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {sub}
              </p>
            </div>
          ))}
        </div>

        {/* ── Flow Metadata ── */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.025)',
          border: '1px solid var(--gg-border)',
          borderRadius: 'var(--gg-radius-sm)',
          padding: 14,
          marginBottom: 16,
        }}>
          <p className="gg-label" style={{ marginBottom: 10 }}>Observed Flow Metadata (Passive Line Ingest)</p>
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 2fr',
            gap: '6px 16px',
            fontSize: 11,
            fontFamily: 'var(--font-mono)',
          }}>
            {([
              ['Source IP:Port', `${alert.source_ip}:${alert.source_port}`],
              ['Destination IP:Port', `${alert.destination_ip}:${alert.destination_port}`],
              ['Protocol', proto(alert.protocol)],
              alert.features?.duration !== undefined ? ['Flow Duration', `${alert.features.duration}s`] : null,
              alert.features?.packet_count !== undefined ? ['Packet Count', String(alert.features.packet_count)] : null,
              alert.features?.byte_count !== undefined ? ['Byte Volume', `${alert.features.byte_count} B`] : null,
              alert.inference_latency_ms !== undefined ? ['Measured Latency', `${alert.inference_latency_ms.toFixed(3)} ms`] : null,
              alert.model_version !== undefined ? ['Model Engine', alert.model_version] : null,
            ] as ([string, string] | null)[]).filter((x): x is [string, string] => x !== null).map(([k, v]) => (
              <div key={k} style={{ display: 'contents' }}>
                <span style={{ color: 'var(--gg-text-3)' }}>{k}</span>
                <span style={{ color: 'var(--gg-text)' }}>{v}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Forensic Evidence (Structured Objects & Observations) ── */}
        {alert.evidence && alert.evidence.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <p className="gg-label" style={{ marginBottom: 8 }}>Structured Forensic Evidence (Measurable Signals)</p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 180, overflowY: 'auto' }}>
              {alert.evidence.map((ev, i) => {
                if (typeof ev === 'object' && ev !== null && 'feature' in ev) {
                  const structEv = ev as StructuredEvidence;
                  return (
                    <div key={i} style={{
                      display: 'flex', flexDirection: 'column', gap: 2,
                      padding: '8px 10px',
                      borderRadius: 6,
                      background: 'rgba(16, 185, 129, 0.04)',
                      border: '1px solid rgba(16, 185, 129, 0.15)',
                      fontSize: 11,
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ color: '#34d399', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                          {structEv.feature}
                        </span>
                        <span style={{ color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)' }}>
                          Observed: {String(structEv.observed_value)}
                        </span>
                      </div>
                      <span style={{ color: 'var(--gg-text-2)' }}>{structEv.interpretation}</span>
                    </div>
                  );
                }
                return (
                  <div key={i} style={{
                    display: 'flex', gap: 8, fontSize: 11, color: 'var(--gg-text-2)',
                    padding: '6px 10px',
                    borderRadius: 6,
                    background: 'rgba(16, 185, 129, 0.04)',
                    border: '1px solid rgba(16, 185, 129, 0.15)',
                  }}>
                    <span style={{ color: '#34d399', flexShrink: 0 }}>✓</span>
                    <span>{String(ev)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ── Analyst Explanation ── */}
        {alert.explanation && (
          <div style={{
            background: 'rgba(6, 182, 212, 0.05)',
            border: '1px solid rgba(6, 182, 212, 0.2)',
            borderRadius: 'var(--gg-radius-sm)',
            padding: 14,
          }}>
            <p className="gg-label" style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6, color: '#22d3ee' }}>
              <Info size={12} />
              Analyst Forensic Assessment
            </p>
            <p style={{ fontSize: 11, color: 'var(--gg-text-2)', lineHeight: 1.5 }}>
              {alert.explanation}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
