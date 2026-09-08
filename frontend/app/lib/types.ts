/**
 * types.ts — Shared TypeScript interfaces for GeoGuards SOC Dashboard
 */

export interface Alert {
  alert_id:              string;
  timestamp:             string;
  model_version?:        string;
  source_ip:             string;
  destination_ip:        string;
  source_port:           number;
  destination_port:      number;
  protocol:              number;
  prediction:            string;
  confidence:            number;
  anomaly_score:         number;
  is_anomaly:            boolean;
  behaviour_score:       number;
  behaviour_type:        string;
  final_risk_score:      number;
  severity:              string;
  dominant_threat:       string;
  evidence:              string[];
  explanation:           string;
  inference_latency_ms?: number;
  features?:             Record<string, number>;
}

export interface Stats {
  flows_processed:                number;
  threats_detected:               number;
  high_risk_alerts:               number;
  anomaly_count:                  number;
  average_inference_latency_ms:   number | null;
  storage_backend:                string;
  model_version:                  string;
  started_at:                     string;
}

export interface HealthStatus {
  status:         string;
  model_loaded:   boolean;
  scaler_loaded:  boolean;
  db_available:   boolean;
  model_version:  string;
}

export interface PcapAnalysisResult {
  message:     string;
  flow_count:  number;
  results:     Alert[];
}

export interface TrendPoint {
  time:    string;
  threats: number;
  benign:  number;
}

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type ApiStatus     = 'ok' | 'error' | 'loading';
