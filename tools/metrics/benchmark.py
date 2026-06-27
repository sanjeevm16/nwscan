# metrics/benchmark.py
import time
from tools.pqc_observability.collectors.kem.kyber import run_kyber as kyber_kem_round

def time_kem_rounds(n: int = 100):
    start = time.perf_counter()
    sizes = []
    for _ in range(n):
        sizes.append(kyber_kem_round())
    end = time.perf_counter()

    return {
        "rounds": n,
        "total_time_s": end - start,
        "avg_time_ms": (end - start) * 1000 / n,
        "avg_pk_len": sum(s["pk_len"] for s in sizes) / n,
        "avg_sk_len": sum(s["sk_len"] for s in sizes) / n,
        "avg_ct_len": sum(s["ct_len"] for s in sizes) / n,
    }
