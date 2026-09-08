import { TopBar } from '../components/TopBar';

function Pillar({
  title, badge, badgeColor, subtitle, items, note
}: {
  title: string; badge: string; badgeColor: string; subtitle: string;
  items: string[]; note?: string;
}) {
  return (
    <div className="gg-card" style={{ padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--gg-text)' }}>{title}</h3>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '3px 9px', borderRadius: 6,
            border: `1px solid ${badgeColor}44`, color: badgeColor, background: `${badgeColor}15`,
            boxShadow: `0 0 10px ${badgeColor}22`,
            letterSpacing: '0.06em', textTransform: 'uppercase' as const,
          }}>{badge}</span>
        </div>
        <p style={{ fontSize: 12, color: 'var(--gg-text-3)' }}>{subtitle}</p>
      </div>
      <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 7 }}>
        {items.map((item, i) => (
          <li key={i} style={{ display: 'flex', gap: 9, fontSize: 12, color: 'var(--gg-text-2)' }}>
            <span style={{ color: '#34d399', flexShrink: 0 }}>✓</span>
            <span>{item}</span>
          </li>
        ))}
      </ul>
      {note && <p style={{ fontSize: 10, color: 'var(--gg-muted)', fontStyle: 'italic', marginTop: 'auto' }}>{note}</p>}
    </div>
  );
}

function FusionWeights() {
  const weights = [
    { label: 'Supervised Classifier', pct: 50, color: '#22d3ee', desc: 'DiodeThreatNet confidence' },
    { label: 'Anomaly Detector',       pct: 25, color: '#fbbf24', desc: 'Isolation Forest score' },
    { label: 'Behaviour Analytics',    pct: 25, color: '#fb923c', desc: 'Statistical heuristic score' },
  ];
  return (
    <div className="gg-card" style={{ padding: 24 }}>
      <div style={{ marginBottom: 18 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--gg-text)' }}>Risk Fusion Engine</h3>
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '3px 9px', borderRadius: 6,
            border: '1px solid rgba(245,158,11,0.4)', color: '#fbbf24',
            background: 'rgba(245,158,11,0.12)', boxShadow: '0 0 10px rgba(245,158,11,0.2)',
            letterSpacing: '0.06em', textTransform: 'uppercase' as const,
          }}>Consensus Architecture</span>
        </div>
        <p style={{ fontSize: 12, color: 'var(--gg-text-3)' }}>
          Combines all three detection pillar scores into a single fused risk score [0–1].
          Weights represent calibrated baseline multi-model consensus fusion.
        </p>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {weights.map((w) => (
          <div key={w.label}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12, marginBottom: 6 }}>
              <span style={{ color: 'var(--gg-text)', fontWeight: 600 }}>{w.label}</span>
              <div style={{ display: 'flex', gap: 12, fontSize: 11 }}>
                <span style={{ color: 'var(--gg-text-3)' }}>{w.desc}</span>
                <span style={{ color: w.color, fontWeight: 800, fontFamily: 'var(--font-mono)' }}>{w.pct}%</span>
              </div>
            </div>
            <div style={{
              height: 6,
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.05)',
              borderRadius: 3,
              overflow: 'hidden',
            }}>
              <div style={{
                height: '100%',
                width: `${w.pct}%`,
                background: `linear-gradient(90deg, ${w.color}88, ${w.color})`,
                boxShadow: `0 0 10px ${w.color}66`,
                borderRadius: 3
              }} />
            </div>
          </div>
        ))}
      </div>
      <div style={{
        marginTop: 18,
        padding: 14,
        background: 'rgba(255, 255, 255, 0.025)',
        border: '1px solid var(--gg-border)',
        borderRadius: 'var(--gg-radius-sm)',
        fontSize: 11,
        color: 'var(--gg-text-3)'
      }}>
        <strong style={{ color: 'var(--gg-cyan)', fontFamily: 'var(--font-mono)' }}>Formula: </strong>
        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--gg-text-2)' }}>
          final_risk = (0.50 × classifier_score) + (0.25 × anomaly_score) + (0.25 × behaviour_score)
        </span>
      </div>
    </div>
  );
}

function ImplVsFuture() {
  const impl = [
    'PCAP flow extraction (Scapy)', '5-tuple flow tracking',
    '21 extracted flow features', 'PyTorch baseline classifier (DiodeThreatNet)',
    'Isolation Forest anomaly detection', 'Behaviour analytics (heuristic)',
    'Risk fusion engine', 'Explainable alerts', 'FastAPI backend',
    'Next.js SOC dashboard', 'Traffic simulator', 'MongoDB / in-memory storage',
  ];
  const future = [
    'Physical data-diode hardware integration', 'Real labeled benign traffic baseline',
    'Model retraining pipeline', 'Threshold calibration', 'Expanded threat taxonomy',
    'TLS/QUIC fingerprinting', 'DGA detection', 'Historical correlation',
    'Production authentication', 'High-performance packet ingestion',
    'Calibrated risk scoring with ground truth',
  ];
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      <div className="gg-card" style={{ padding: 24 }}>
        <p className="gg-label" style={{ color: '#34d399', marginBottom: 14 }}>✓ Implemented System</p>
        <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 6 }}>
          {impl.map((item, i) => (
            <li key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--gg-text-2)' }}>
              <span style={{ color: '#34d399', flexShrink: 0 }}>✓</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="gg-card" style={{ padding: 24 }}>
        <p className="gg-label" style={{ color: '#22d3ee', marginBottom: 14 }}>→ Production Roadmap</p>
        <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 6 }}>
          {future.map((item, i) => (
            <li key={i} style={{ display: 'flex', gap: 8, fontSize: 12, color: 'var(--gg-text-3)' }}>
              <span style={{ color: '#22d3ee', flexShrink: 0 }}>→</span>
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default function DetectionEngine() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100%' }}>
      <TopBar
        title="Detection Engine"
        subtitle="3-Pillar passive multi-model consensus architecture · Explainability and risk fusion"
      />

      <div style={{ flex: 1, padding: 24, display: 'flex', flexDirection: 'column', gap: 20 }}>
        {/* Pillars */}
        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
          <Pillar
            title="1. Supervised Classifier"
            badge="PyTorch MLP"
            badgeColor="#22d3ee"
            subtitle="DiodeThreatNet — Multi-class neural network"
            items={[
              '21 extracted flow metadata features',
              'Classification: Benign, Flood, DNS Tunneling, C2 Beaconing',
              'Outputs class probability distribution',
              'Sub-millisecond inference per flow',
            ]}
            note="Trained on baseline synthetic attack traffic."
          />
          <Pillar
            title="2. Anomaly Detection"
            badge="Isolation Forest"
            badgeColor="#fbbf24"
            subtitle="Unsupervised outlier & deviation detection"
            items={[
              'No attack signature dependency',
              'Detects statistical outliers in feature space',
              'Normalized anomaly score [0–1]',
              'Flags novel and zero-day threat patterns',
            ]}
            note="Unsupervised model for zero-day identification."
          />
          <Pillar
            title="3. Behaviour Analytics"
            badge="Heuristic Engine"
            badgeColor="#fb923c"
            subtitle="Domain-specific network traffic heuristic rules"
            items={[
              'Beacon regularity / jitter analysis',
              'High-frequency UDP / DNS payload ratio',
              'Port scan & sweep pattern matching',
              'Data exfiltration volume heuristics',
            ]}
            note="Domain expert heuristics for passive metadata."
          />
        </section>

        {/* Fusion */}
        <FusionWeights />

        {/* Status */}
        <ImplVsFuture />
      </div>
    </div>
  );
}
