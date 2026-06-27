# metrics/telemetry.py
import json
from .benchmark import time_kem_rounds

def collect_pqc_posture():
    kyber_stats = time_kem_rounds(200)

    posture = {
        "algorithms": {
            "kyber512": {
                "avg_time_ms": kyber_stats["avg_time_ms"],
                "avg_pk_len": kyber_stats["avg_pk_len"],
                "avg_sk_len": kyber_stats["avg_sk_len"],
                "avg_ct_len": kyber_stats["avg_ct_len"],
            }
        },
        "summary": {
            "pqc_ready": kyber_stats["avg_time_ms"] < 5.0  # your threshold
        }
    }
    return posture

def export_posture(path="pqc_posture.json"):
    data = collect_pqc_posture()
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
