"""
Simulation & Threat Telemetry Dataset Recorder
Automatically records every simulated attack, live packet classification, and user triage
decision into structured datasets ready for:
1. Machine Learning Model Retraining (LightGBM/XGBoost tabular dataset in CSV)
2. Fine-Tuning Self-Hosted Ollama LLMs (Cybersecurity instruction-tuning dataset in JSONL)
3. Audit history & historical threat replay
"""

import os
import csv
import json
import time
from datetime import datetime
import threading

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))
CSV_FILE = os.path.join(DATA_DIR, "training_features.csv")
JSONL_FILE = os.path.join(DATA_DIR, "simulation_history.jsonl")
LLM_DATASET_FILE = os.path.join(DATA_DIR, "llm_training_pairs.jsonl")

FEATURE_COLUMNS = [
    "Flow Duration",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Total Fwd Packets",
    "Total Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "RST Flag Count",
    "ACK Flag Count",
    "Idle Mean",
    "Idle Max"
]

LOCK = threading.Lock()


class SimulationRecorder:
    def __init__(self):
        self._ensure_storage()

    def _ensure_storage(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(CSV_FILE):
            with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                headers = ["timestamp", "session_id", "src_ip", "dst_ip", "attack_category", "is_attack"] + FEATURE_COLUMNS
                writer.writerow(headers)

    def record_event(self, packet_data, features, prediction_result, ground_truth=None, source="simulation"):
        """
        Records a telemetry event into both CSV (for LightGBM) and JSONL (for LLM fine-tuning).
        """
        with LOCK:
            now_iso = datetime.now().isoformat()
            ts = time.time()
            session_id = f"sim_{int(ts)}_{int(time.time() * 1000) % 1000}"

            src_ip = packet_data[0].get("src_ip", "0.0.0.0") if packet_data and isinstance(packet_data, list) else "0.0.0.0"
            dst_ip = packet_data[0].get("dst_ip", "0.0.0.0") if packet_data and isinstance(packet_data, list) else "0.0.0.0"

            is_attack = ground_truth.get("is_attack") if isinstance(ground_truth, dict) else prediction_result.get("is_attack", False)
            category = ground_truth.get("category") if isinstance(ground_truth, dict) else prediction_result.get("category", "BENIGN")

            feat_dict = features if isinstance(features, dict) else {}

            # 1. Append to Tabular CSV for Model Retraining
            row = [now_iso, session_id, src_ip, dst_ip, category, 1 if is_attack else 0]
            for col in FEATURE_COLUMNS:
                row.append(feat_dict.get(col, 0.0))

            try:
                with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow(row)
            except Exception as e:
                print(f"[SimulationRecorder] Error writing CSV: {e}")

            # 2. Append to Full JSONL Replay Log
            record = {
                "timestamp": now_iso,
                "session_id": session_id,
                "source": source,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "ground_truth": ground_truth or {"category": category, "is_attack": is_attack},
                "prediction": {
                    "classification": prediction_result.get("classification"),
                    "category": prediction_result.get("category"),
                    "confidence": prediction_result.get("confidence"),
                    "risk_score": prediction_result.get("risk_score"),
                    "threat_severity": prediction_result.get("threat_severity"),
                    "action_taken": prediction_result.get("action_taken"),
                    "latency_ms": prediction_result.get("latency_ms")
                },
                "features": feat_dict,
                "packet_sample": packet_data[:3] if isinstance(packet_data, list) else []
            }

            try:
                with open(JSONL_FILE, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            except Exception as e:
                print(f"[SimulationRecorder] Error writing JSONL: {e}")

            # 3. Generate Instruction-Tuning Pair for Ollama LLM Fine-Tuning
            try:
                llm_pair = {
                    "instruction": f"Analyze network flow telemetry and determine threat category and mitigation for traffic from {src_ip} targeting {dst_ip}.",
                    "input": (
                        f"Features: {json.dumps({k: feat_dict[k] for k in FEATURE_COLUMNS if k in feat_dict})}\n"
                        f"Packets Captured: {len(packet_data) if isinstance(packet_data, list) else 1}"
                    ),
                    "output": (
                        f"Threat Assessment: {category} ({'MALICIOUS' if is_attack else 'BENIGN'})\n"
                        f"Recommended Mitigation: {prediction_result.get('action_taken', 'Traffic Allowed')}\n"
                        f"Risk Score: {prediction_result.get('risk_score', 10.0)}/100."
                    )
                }
                with open(LLM_DATASET_FILE, "a", encoding="utf-8") as f:
                    f.write(json.dumps(llm_pair) + "\n")
            except Exception as e:
                print(f"[SimulationRecorder] Error writing LLM pairs: {e}")

            return {
                "recorded": True,
                "session_id": session_id,
                "category": category,
                "is_attack": is_attack
            }

    def get_stats(self):
        """Returns statistics on recorded simulation data."""
        with LOCK:
            total_samples = 0
            attack_count = 0
            benign_count = 0
            category_counts = {}

            if os.path.exists(CSV_FILE):
                try:
                    with open(CSV_FILE, "r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        for r in reader:
                            total_samples += 1
                            cat = r.get("attack_category", "UNKNOWN")
                            is_atk = r.get("is_attack") in ("1", 1, True, "True")
                            if is_atk:
                                attack_count += 1
                            else:
                                benign_count += 1
                            category_counts[cat] = category_counts.get(cat, 0) + 1
                except Exception as e:
                    print(f"[SimulationRecorder] Stats error: {e}")

            llm_samples = 0
            if os.path.exists(LLM_DATASET_FILE):
                try:
                    with open(LLM_DATASET_FILE, "r", encoding="utf-8") as f:
                        llm_samples = sum(1 for _ in f)
                except Exception:
                    pass

            return {
                "total_recorded_events": total_samples,
                "attack_events": attack_count,
                "benign_events": benign_count,
                "categories": category_counts,
                "llm_instruction_pairs": llm_samples,
                "csv_path": CSV_FILE,
                "jsonl_path": JSONL_FILE,
                "llm_dataset_path": LLM_DATASET_FILE,
                "ready_for_training": total_samples >= 10
            }


global_recorder = SimulationRecorder()
