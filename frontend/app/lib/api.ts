/**
 * api.ts — Centralized API client for GeoGuards SOC Dashboard (SIH 26145)
 * Uses NEXT_PUBLIC_API_BASE_URL env variable. Falls back to localhost:8000.
 */

import type { Alert, Stats, HealthStatus, PcapAnalysisResult, CorrelationCluster, StreamingReplayResponse } from './types';

const BASE = (process.env.NEXT_PUBLIC_API_BASE_URL ?? 'http://localhost:8000').replace(/\/$/, '');

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`API ${res.status}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export const API = {
  health: ()                   => apiFetch<HealthStatus>('/api/v1/health'),
  stats:  ()                   => apiFetch<Stats>('/api/v1/stats'),
  alerts: (limit = 100)        => apiFetch<Alert[]>(`/api/v1/alerts?limit=${limit}`),
  flows:  (limit = 100)        => apiFetch<Alert[]>(`/api/v1/flows?limit=${limit}`),
  alert:  (id: string)         => apiFetch<Alert>(`/api/v1/alerts/${id}`),
  correlationClusters: ()      => apiFetch<CorrelationCluster[]>('/api/v1/correlation/clusters'),
  benchmarkSummary: ()         => apiFetch<Record<string, unknown>>('/api/v1/benchmark/summary'),

  analyzeFlow: (flow: Record<string, unknown>) =>
    apiFetch<Alert>('/api/v1/analyze-flow', {
      method: 'POST',
      body: JSON.stringify(flow),
    }),

  streamPcap: async (file: File, speed = 0.0): Promise<StreamingReplayResponse> => {
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch(`${BASE}/api/v1/stream-pcap?speed=${speed}`, { method: 'POST', body: fd });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(`API ${res.status}: ${text}`);
    }
    return res.json();
  },

  analyzePcap: async (file: File): Promise<PcapAnalysisResult> => {
    const fd = new FormData();
    fd.append('file', file);
    const res = await fetch(`${BASE}/api/v1/analyze-pcap`, { method: 'POST', body: fd });
    if (!res.ok) {
      const text = await res.text().catch(() => res.statusText);
      throw new Error(`API ${res.status}: ${text}`);
    }
    return res.json();
  },
};

export { BASE };
