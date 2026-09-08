import { ArrowDown } from 'lucide-react';

export function NetworkTopology() {
  const nodes = [
    {
      label: 'Protected Network',
      sub: 'Production / Source Network',
      color: '#22d3ee',
      glow: 'rgba(6,182,212,0.2)',
      bg: 'rgba(6,182,212,0.06)',
      border: 'rgba(6,182,212,0.3)',
    },
    {
      label: 'One-Way Ingestion',
      sub: 'Traffic Copy — No Return Path (Diode)',
      color: '#f59e0b',
      glow: 'rgba(245,158,11,0.2)',
      bg: 'rgba(245,158,11,0.06)',
      border: 'rgba(245,158,11,0.3)',
    },
    {
      label: 'Analytics Enclave',
      sub: 'Passive Multi-Model AI Engine',
      color: '#34d399',
      glow: 'rgba(16,185,129,0.2)',
      bg: 'rgba(16,185,129,0.06)',
      border: 'rgba(16,185,129,0.3)',
    },
    {
      label: 'SOC Dashboard',
      sub: 'Analyst Threat Investigation',
      color: '#a78bfa',
      glow: 'rgba(167,139,250,0.2)',
      bg: 'rgba(167,139,250,0.06)',
      border: 'rgba(167,139,250,0.3)',
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch', gap: 0 }}>
        {nodes.map((node, i) => (
          <div key={node.label}>
            <div style={{
              padding: '12px 16px',
              border: `1px solid ${node.border}`,
              borderRadius: 'var(--gg-radius-sm)',
              background: node.bg,
              backdropFilter: 'blur(12px)',
              WebkitBackdropFilter: 'blur(12px)',
              boxShadow: `0 4px 16px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.08), 0 0 12px ${node.glow}`,
              transition: 'all 0.2s ease',
            }}>
              <div style={{
                fontSize: 11,
                fontWeight: 800,
                color: node.color,
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
                textShadow: `0 0 10px ${node.color}66`,
              }}>
                {node.label}
              </div>
              <div style={{ fontSize: 10, color: 'var(--gg-text-3)', marginTop: 2 }}>{node.sub}</div>
            </div>
            {i < nodes.length - 1 && (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '3px 0' }}>
                <div style={{ width: 1, height: 6, background: 'rgba(255,255,255,0.1)' }} />
                <ArrowDown size={13} color="var(--gg-cyan)" className="animate-flow-down" />
                <div style={{ width: 1, height: 6, background: 'rgba(255,255,255,0.1)' }} />
              </div>
            )}
          </div>
        ))}
      </div>

      <div style={{
        marginTop: 14,
        paddingTop: 12,
        borderTop: '1px solid var(--gg-border)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11, marginBottom: 6 }}>
          <span style={{ color: 'var(--gg-text-3)' }}>Return Traffic Probing</span>
          <span style={{
            color: 'var(--gg-green)',
            fontWeight: 800,
            fontFamily: 'var(--font-mono)',
            background: 'rgba(16,185,129,0.1)',
            padding: '2px 8px',
            borderRadius: 4,
            border: '1px solid rgba(16,185,129,0.3)',
            boxShadow: '0 0 8px rgba(16,185,129,0.2)',
          }}>
            0 PACKETS (BLOCKED)
          </span>
        </div>
        <p style={{ fontSize: 10, color: 'var(--gg-muted)', lineHeight: 1.5 }}>
          Passive monitoring only. Physical one-way isolation ensures zero reverse-channel risk to protected OT/critical subnets.
        </p>
      </div>
    </div>
  );
}
