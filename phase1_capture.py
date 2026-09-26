"""Phase 1: capture ~10 real footprints (mixed attack/benign) to data/footprints.jsonl."""
import json, sys, time
from collector.collector import capture_episode

# (kind, family, seed) — the session stream. Ordered so families recur:
# config_reload is a benign-but-anomalous family (clean restart) that the cheap
# tier flags, so memory has something to learn and later suppress. Attacks recur
# too (segfault twice) to show second-pass recognition from memory.
PLAN = [
    ("benign", "normal_requests",     11),  # zero-signal -> cheap ignores (free)
    ("attack", "malformed_segfault",  23),  # cold -> escalate -> malicious stored
    ("benign", "config_reload",       31),  # anomalous benign, cold -> escalate -> benign stored
    ("attack", "port_scan",           21),  # escalate -> malicious
    ("benign", "health_checks",       12),  # zero-signal -> ignore
    ("attack", "resource_exhaustion", 24),  # escalate -> malicious
    ("benign", "config_reload",       32),  # surface-varied -> gate SUPPRESSES from memory
    ("attack", "auth_bruteforce",     22),  # escalate -> malicious
    ("benign", "file_ops",            13),  # zero-signal -> ignore
    ("attack", "malformed_segfault",  25),  # repeat attack -> recognized from memory (escalate)
    ("benign", "config_reload",       33),  # surface-varied -> SUPPRESS again
    ("benign", "normal_requests",     14),  # zero-signal -> ignore
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
