"""
anomaly_detector.py
-------------------
Isolation Forest-based anomaly detector for passive cyber threat detection.
Used as a COMPLEMENTARY signal alongside the supervised DiodeThreatNet classifier.

This detector identifies unusual/anomalous flow behaviour relative to a synthetic
benign baseline. It does NOT identify specific attack families — that is the role
of the supervised classifier and behaviour analytics engine.

Input  : engineered feature vector (dict or numpy array)
Output : anomaly_score (float 0-1, higher = more anomalous)
         is_anomaly (bool)
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler


# ── Feature names used by this detector ───────────────────────────────────────
ANOMALY_FEATURES = [
    "iat_mean",
    "iat_std",
    "pkt_len_mean",
    "pkt_len_std",
    "payload_entropy",
    "syn_ratio",
    "tcp_rst_ratio",
    "tcp_fin_ratio",
    "duration",
    "packet_count",
]

# ── Threshold: anomaly score above this is flagged as anomalous ───────────────
DEFAULT_ANOMALY_THRESHOLD = 0.55


def _generate_benign_baseline(n_samples: int = 2000, seed: int = 42) -> np.ndarray:
    """
    Generate a deterministic synthetic benign traffic baseline for fitting the
    Isolation Forest.  All parameters are chosen to represent typical internal
    LAN traffic patterns.

    IMPORTANT: This is a synthetic baseline used for prototype demonstration only.
    Replace with real labeled benign traffic data before production deployment.
    """
    rng = np.random.default_rng(seed)

    iat_mean      = rng.exponential(scale=0.05,  size=n_samples)      # ~50ms IAT
    iat_std       = rng.exponential(scale=0.02,  size=n_samples)      # low variance
    pkt_len_mean  = rng.normal(loc=500,  scale=100, size=n_samples)   # ~500 B
    pkt_len_std   = rng.normal(loc=80,   scale=20,  size=n_samples)   # moderate std
    payload_ent   = rng.normal(loc=5.0,  scale=0.8, size=n_samples)   # ~5 bits entropy
    syn_ratio     = rng.beta(a=1, b=20,  size=n_samples)              # low SYN ratio
    rst_ratio     = rng.beta(a=1, b=30,  size=n_samples)              # very low RST
    fin_ratio     = rng.beta(a=2, b=15,  size=n_samples)              # low FIN
    duration      = rng.exponential(scale=2.0,   size=n_samples)      # ~2s flows
    pkt_count     = rng.integers(5, 100,          size=n_samples).astype(float)

    # Clip to realistic ranges
    pkt_len_mean  = np.clip(pkt_len_mean, 40, 1500)
    pkt_len_std   = np.clip(pkt_len_std,  0,  500)
    payload_ent   = np.clip(payload_ent,  0,  8.0)

    return np.column_stack([
        iat_mean, iat_std, pkt_len_mean, pkt_len_std,
        payload_ent, syn_ratio, rst_ratio, fin_ratio,
        duration, pkt_count,
    ])


class AnomalyDetector:
    """
    Isolation Forest anomaly detector for network flow data.

    Scores each flow relative to a benign baseline.  The score is normalised
    to [0, 1] so it can be combined with the supervised classifier confidence
    and behaviour score in the RiskFusionEngine.

    Usage
    -----
    detector = AnomalyDetector()
    detector.fit()          # fit on synthetic benign baseline
    result = detector.score(features_dict)
    # result = {"anomaly_score": 0.73, "is_anomaly": True}
    """

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        threshold: float = DEFAULT_ANOMALY_THRESHOLD,
        random_state: int = 42,
    ):
        self.contamination  = contamination
        self.n_estimators   = n_estimators
        self.threshold      = threshold
        self.random_state   = random_state

        self._forest       = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
        )
        self._score_scaler = MinMaxScaler(feature_range=(0, 1))
        self._fitted       = False

    # ── Public API ─────────────────────────────────────────────────────────────

    def fit(self, X: np.ndarray | None = None) -> None:
        """
        Fit the Isolation Forest on benign traffic.

        Parameters
        ----------
        X : np.ndarray, shape (n_samples, 10), optional
            If None, uses the synthetic benign baseline.
        """
        if X is None:
            X = _generate_benign_baseline()

        self._forest.fit(X)

        # Compute raw scores on benign data to calibrate the scaler
        raw_scores = -self._forest.score_samples(X)  # higher = more anomalous
        self._score_scaler.fit(raw_scores.reshape(-1, 1))
        self._fitted = True

    def score(self, features: dict) -> dict:
        """
        Score a single flow.

        Parameters
        ----------
        features : dict
            Must contain keys listed in ANOMALY_FEATURES.
            Missing keys default to 0.0.

        Returns
        -------
        dict with keys:
            anomaly_score : float  [0, 1]  — 0 = normal, 1 = maximally anomalous
            is_anomaly    : bool           — True if score ≥ threshold
        """
        if not self._fitted:
            self.fit()

        vec = np.array([[
            float(features.get(f, 0.0)) for f in ANOMALY_FEATURES
        ]])

        raw_score  = -self._forest.score_samples(vec)[0]  # higher = more anomalous
        norm_score = float(
            np.clip(self._score_scaler.transform([[raw_score]])[0][0], 0.0, 1.0)
        )

        return {
            "anomaly_score": round(norm_score, 4),
            "is_anomaly"   : norm_score >= self.threshold,
        }

    def score_batch(self, features_list: list[dict]) -> list[dict]:
        """Score a batch of flows."""
        return [self.score(f) for f in features_list]


# ── Module-level singleton (lazy-initialised) ─────────────────────────────────
_detector_instance: AnomalyDetector | None = None


def get_detector() -> AnomalyDetector:
    """Return the module-level AnomalyDetector, fitting on first call."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = AnomalyDetector()
        _detector_instance.fit()
    return _detector_instance


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    det = get_detector()

    benign_flow = {
        "iat_mean": 0.05, "iat_std": 0.02, "pkt_len_mean": 500,
        "pkt_len_std": 80, "payload_entropy": 5.0, "syn_ratio": 0.02,
        "tcp_rst_ratio": 0.01, "tcp_fin_ratio": 0.05,
        "duration": 1.8, "packet_count": 20,
    }
    syn_flood_flow = {
        "iat_mean": 0.0003, "iat_std": 0.00005, "pkt_len_mean": 64,
        "pkt_len_std": 2.0, "payload_entropy": 0.15, "syn_ratio": 0.99,
        "tcp_rst_ratio": 0.0, "tcp_fin_ratio": 0.0,
        "duration": 0.5, "packet_count": 800,
    }

    print("Benign flow  :", det.score(benign_flow))
    print("SYN Flood    :", det.score(syn_flood_flow))
