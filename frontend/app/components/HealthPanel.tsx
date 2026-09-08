'use client';

import { useEffect, useState } from 'react';
import { API } from '../lib/api';
import type { HealthStatus, Stats } from '../lib/types';
import { Server } from 'lucide-react';

function Row({ label, value, ok }: { label: string; value: string; ok?: boolean }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '5px 0' }}>
      <span style={{ fontSize: 11, color: 'var(--gg-muted)' }}>{label}</span>
      <span style={{
        fontSize: 11,
        fontWeight: 600,
        color: ok === true ? 'var(--gg-green)' : ok === false ? 'var(--gg-red)' : 'var(--gg-text-2)',
        fontFamily: 'var(--font-mono)',
      }}>
        {value}
      </span>
    </div>
  );
}

export function HealthPanel() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [stats,  setStats]  = useState<Stats | null>(null);

  useEffect(() => {
    const load = async () => {
      try { setHealth(await API.health()); } catch { /* offline */ }
      try { setStats(await API.stats()); }  catch { /* offline */ }
    };
    load();
    const id = setInterval(load, 15_000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="gg-card" style={{ padding: 16 }}>
      <p className="gg-label" style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 12 }}>
        <Server size={11} />
        System Health
      </p>
      <div style={{ borderTop: '1px solid var(--gg-border)' }}>
        <Row label="API"        value={health?.status === 'ok' ? 'OPERATIONAL' : 'OFFLINE'}     ok={health?.status === 'ok'} />
        <Row label="Model"      value={health?.model_loaded ? 'LOADED' : 'UNAVAILABLE'}          ok={health?.model_loaded} />
        <Row label="Scaler"     value={health?.scaler_loaded ? 'LOADED' : 'UNAVAILABLE'}         ok={health?.scaler_loaded} />
        <Row label="Storage"    value={stats?.storage_backend === 'mongodb' ? 'MongoDB' : 'In-Memory'} />
        <Row label="Model ver." value={health?.model_version ?? '—'} />
        {stats?.average_inference_latency_ms != null && (
          <Row label="Avg latency" value={`${stats.average_inference_latency_ms.toFixed(2)} ms`} />
        )}
      </div>
      {!health && (
        <p style={{ fontSize: 10, color: 'var(--gg-red)', marginTop: 8 }}>Backend unreachable</p>
      )}
    </div>
  );
}
