"""Phase 1: capture ~10 real footprints (mixed attack/benign) to data/footprints.jsonl."""
import json, sys, time
from collector.collector import capture_episode

# (kind, family, seed) — mix of attack and benign families
PLAN = [
    ("benign", "normal_requests", 11),
    ("attack", "port_scan",        21),
    ("benign", "health_checks",    12),
    ("attack", "auth_bruteforce",  22),
    ("benign", "file_ops",         13),
    ("attack", "malformed_segfault", 23),
    ("benign", "normal_requests",  14),
    ("attack", "resource_exhaustion", 24),
    ("benign", "health_checks",    15),
    ("attack", "malformed_segfault", 25),
]

OUT = "data/footprints.jsonl"

def main():
    footprints = []
    with open(OUT, "w") as f:
        for i, (kind, family, seed) in enumerate(PLAN):
            eid = f"ep{i:02d}-{family}"
            print(f"\n=== [{i+1}/{len(PLAN)}] {eid} ({kind}) ===", flush=True)
            fp = capture_episode(eid, kind, family, seed)
            f.write(json.dumps(fp) + "\n"); f.flush()
            footprints.append(fp)
            c = fp["cheap_features"]
            print(f"  label={fp['ground_truth_label']:6s} "
                  f"restarts={c['restart_count']} oom={c['oom_kills']} "
                  f"nonzero_exit={c['nonzero_exit_count']} fail_rate={c['failure_rate']} "
                  f"err_types={c['distinct_error_types']} conn_refused={c['conn_refused_count']} "
                  f"cpu_spike={c['cpu_spike']} mem_spike={c['mem_spike']}", flush=True)
    print(f"\n[OK] wrote {len(footprints)} footprints to {OUT}")

if __name__ == "__main__":
    main()
