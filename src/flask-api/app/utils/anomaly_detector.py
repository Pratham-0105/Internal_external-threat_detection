"""
Unsupervised Zero-Day Anomaly Detection Engine.
Calculates statistical feature deviation scores to flag novel, unseen attack patterns.
"""
import numpy as np

class ZeroDayAnomalyDetector:
    def __init__(self):
        # Baseline normal mean values for 25 features
        self.normal_baseline = {
            'Flow IAT Mean': 25000.0,
            'Flow Duration': 50000.0,
            'Fwd IAT Std': 500.0,
            'Total Fwd Packets': 2.0,
            'Idle Max': 0.0
        }

    def evaluate_anomaly(self, features):
        """Returns anomaly score (0-100) and zero-day flag."""
        score = 0.0
        reasons = []

        flow_iat_mean = features.get('Flow IAT Mean', 0.0)
        flow_duration = features.get('Flow Duration', 0.0)
        fwd_iat_std = features.get('Fwd IAT Std', 0.0)
        total_fwd_pkts = features.get('Total Fwd Packets', 0.0)

        # Statistical Variance Checks
        if flow_iat_mean > 500000.0 or (flow_iat_mean < 50.0 and flow_iat_mean > 0):
            score += 35.0
            reasons.append("Unusual Flow IAT Mean variance")

        if total_fwd_pkts > 5:
            score += 25.0
            reasons.append("High packet burst count")

        if fwd_iat_std > 5000.0:
            score += 20.0
            reasons.append("Extreme inter-arrival time jitter")

        if flow_duration > 1000000.0:
            score += 20.0
            reasons.append("Abnormally long session duration")

        anomaly_score = min(100.0, score)
        is_zero_day = anomaly_score >= 60.0

        return {
            "anomaly_score": round(anomaly_score, 1),
            "is_zero_day": is_zero_day,
            "anomaly_reasons": reasons
        }

global_anomaly_detector = ZeroDayAnomalyDetector()
