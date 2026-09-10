# Model Comparison: Baseline V1 vs Expanded V2

### Summary of Differences
- **Model V1 Baseline:** Uses the exact 6 lightweight flow features (`iat_mean`, `iat_std`, `pkt_len_mean`, `pkt_len_std`, `payload_entropy`, `syn_ratio`). Ultra-low latency inference.
- **Model V2 Expanded:** Uses 25 bi-directional flow and protocol metadata attributes (duration, bytes/s, packets/s, subflow ratios, TCP flags).

### Performance Metrics:
- V1 F1: **0.9112** | Latency: **0.074 ms** (P95: 0.117 ms)
- V2 F1: **0.9560** | Latency: **0.114 ms** (P95: 0.216 ms)
