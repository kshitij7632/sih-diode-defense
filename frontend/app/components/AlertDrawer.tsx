'use client';

import { X, Info, ShieldAlert } from 'lucide-react';
import type { Alert } from '../lib/types';
import { SeverityBadge, RiskBar } from './SeverityBadge';

const THREAT_COLORS: Record<string, string> = {
  'SYN/UDP Flood': '#f87171',
  'DNS Tunneling': '#22d3ee',
  'C2 Beaconing':  '#fb923c',
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
      <div className="gg-modal-panel" onClick={(e) => e.stopPropagation()}>

        {/* ── Header ── */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
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
                {alert.dominant_threat}
              </h2>
              <SeverityBadge severity={alert.severity} />
            </div>
            <p style={{ fontSize: 11, color: 'var(--gg-text-3)', fontFamily: 'var(--font-mono)' }}>
              {alert.alert_id} · {new Date(alert.timestamp).toLocaleTimeString('en-GB', { hour12: false })}
              {alert.model_version && ` · ${alert.model_version}`}
            </p>
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
          padding: 18,
          borderRadius: 'var(--gg-radius-sm)',
          background: 'rgba(255, 255, 255, 0.025)',
          border: '1px solid var(--gg-border)',
          marginBottom: 20,
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <span className="gg-label">Fused Risk Score</span>
            <span style={{
              fontSize: 16,
              fontWeight: 800,
              fontFamily: 'var(--font-mono)',
              color: threatColor,
              textShadow: `0 0 12px ${threatColor}66`,
            }}>
              {Math.round(alert.final_risk_score * 100)} / 100
            </span>
          </div>
          <RiskBar score={alert.final_risk_score} severity={alert.severity} />
          <p style={{ fontSize: 10, color: 'var(--gg-muted)', marginTop: 8 }}>
            50% supervised · 25% anomaly · 25% behaviour — baseline passive consensus fusion
          </p>
        </div>

        {/* ── Detection Pillar Scores ── */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 20 }}>
          {[
            { label: 'Classifier',  value: pct(alert.confidence),      sub: alert.prediction, color: '#34d399' },
            { label: 'Anomaly',     value: pct(alert.anomaly_score),    sub: alert.is_anomaly ? 'FLAGGED' : 'Normal', color: '#fbbf24' },
            { label: 'Behaviour',   value: pct(alert.behaviour_score),  sub: alert.behaviour_type || '—', color: '#22d3ee' },
          ].map(({ label, value, sub, color }) => (
            <div key={label} style={{
              background: 'rgba(255, 255, 255, 0.03)',
              backdropFilter: 'blur(12px)',
              WebkitBackdropFilter: 'blur(12px)',
              border: '1px solid var(--gg-border)',
              borderRadius: 'var(--gg-radius-sm)',
              padding: '16px 14px',
              textAlign: 'center',
              boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.06)',
            }}>
              <p className="gg-label" style={{ marginBottom: 6 }}>{label}</p>
              <p style={{
                fontSize: 22,
                fontWeight: 800,
                color: color,
                fontFamily: 'var(--font-mono)',
                textShadow: `0 0 12px ${color}44`,
              }}>
                {value}
              </p>
              <p style={{ fontSize: 11, color: 'var(--gg-text-2)', marginTop: 4, fontWeight: 500 }}>{sub}</p>
            </div>
          ))}
        </div>

        {/* ── Flow Metadata ── */}
        <div style={{
          background: 'rgba(255, 255, 255, 0.025)',
          border: '1px solid var(--gg-border)',
          borderRadius: 'var(--gg-radius-sm)',
          padding: 18,
          marginBottom: 20,
        }}>
          <p className="gg-label" style={{ marginBottom: 12 }}>Extracted Flow 5-Tuple & Metadata</p>
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 2fr',
            gap: '8px 24px',
            fontSize: 11,
            fontFamily: 'var(--font-mono)',
          }}>
            {([
              ['Source',       `${alert.source_ip}:${alert.source_port}`],
              ['Destination',  `${alert.destination_ip}:${alert.destination_port}`],
              ['Protocol',     proto(alert.protocol)],
              alert.features?.duration !== undefined ? ['Duration', `${alert.features.duration}s`] : null,
              alert.features?.packet_count !== undefined ? ['Packets', String(alert.features.packet_count)] : null,
              alert.features?.byte_count !== undefined ? ['Bytes', String(alert.features.byte_count)] : null,
              alert.inference_latency_ms !== undefined ? ['Inference Latency', `${alert.inference_latency_ms.toFixed(2)} ms`] : null,
            ] as ([string, string] | null)[]).filter((x): x is [string, string] => x !== null).map(([k, v]) => (
              <div key={k} style={{ display: 'contents' }}>
                <span style={{ color: 'var(--gg-text-3)' }}>{k}</span>
                <span style={{ color: 'var(--gg-text)' }}>{v}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Evidence ── */}
        {alert.evidence && alert.evidence.length > 0 && (
          <div style={{ marginBottom: 20 }}>
            <p className="gg-label" style={{ marginBottom: 10 }}>Detection Evidence</p>
            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 6 }}>
              {alert.evidence.map((ev, i) => (
                <li key={i} style={{
                  display: 'flex', gap: 10, fontSize: 12, color: 'var(--gg-text-2)',
                  padding: '8px 12px',
                  borderRadius: 6,
                  background: 'rgba(16, 185, 129, 0.05)',
                  border: '1px solid rgba(16, 185, 129, 0.15)',
                }}>
                  <span style={{ color: '#34d399', flexShrink: 0 }}>✓</span>
                  <span>{ev}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* ── Analyst Explanation ── */}
        {alert.explanation && (
          <div style={{
            background: 'rgba(6, 182, 212, 0.05)',
            border: '1px solid rgba(6, 182, 212, 0.2)',
            borderRadius: 'var(--gg-radius-sm)',
            padding: 18,
          }}>
            <p className="gg-label" style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, color: '#22d3ee' }}>
              <Info size={12} />
              Analyst Explanation
            </p>
            <p style={{ fontSize: 12, color: 'var(--gg-text-2)', lineHeight: 1.6 }}>
              {alert.explanation}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
