# GeoGuards Model Evaluation Report

**Generated:** 2026-09-10T13:06:38.180238

## 1. Primary In-Distribution Test Results (Model V1 vs V2)

| Metric | Model V1 (6-Feature Baseline) | Model V2 (25-Feature Expanded) |
|---|---|---|
| **Architecture** | DiodeThreatNet (6→64→32→4) | DiodeThreatNetV2 (25→128→64→32→4) |
| **Accuracy** | **97.21%** | **99.00%** |
| **Macro Precision** | 0.9401 | 0.9843 |
| **Macro Recall** | 0.8913 | 0.9344 |
| **Macro F1 Score** | **0.9112** | **0.9560** |
| **Weighted F1 Score** | 0.9710 | 0.9895 |
| **Benign FPR (False Alarm Rate)** | 1.778% | 0.311% |
| **Threat FNR (Miss Rate)** | 3.499% | 1.587% |
| **Avg Inference Latency** | **0.074 ms** | **0.114 ms** |
| **P95 Inference Latency** | **0.117 ms** | **0.216 ms** |

## 2. Per-Class Breakdown (Model V1 Baseline)

| Threat Class | Precision | Recall | F1 Score | Test Samples |
|---|---|---|---|---|
| **Benign** | 0.9602 | 0.9822 | **0.9711** | 4,500 |
| **SYN/UDP Flood** | 0.9904 | 0.9840 | **0.9872** | 4,500 |
| **DNS Tunneling** | 0.9819 | 0.9954 | **0.9886** | 435 |
| **C2 Beaconing** | 0.8279 | 0.6034 | **0.6980** | 295 |
| | Pred Benign | Pred SYN/UDP Flood | Pred DNS Tunneling | Pred C2 Beaconing |
|---|---|---|---|---|
| **True Benign** | 4,420 | 36 | 8 | 36 |
| **True SYN/UDP Flood** | 71 | 4,428 | 0 | 1 |
| **True DNS Tunneling** | 2 | 0 | 433 | 0 |
| **True C2 Beaconing** | 110 | 7 | 0 | 178 |

