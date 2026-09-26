"""Phase 1: capture ~10 real footprints (mixed attack/benign) to data/footprints.jsonl."""
import json, sys, time
from collector.collector import capture_episode

# (kind, family, seed) — a longer session stream (Phase 3). Each family recurs
# with different seeds (the clients vary counts/payloads/ordering per seed = real
# surface variation). config_reload is the benign-but-anomalous family memory can
# learn and later suppress; the zero-signal benigns are handled free by the cheap
# tier. Front-loaded cold escalations, back-loaded suppressions + ignores.
PLAN = [
    ("attack", "malformed_segfault",  101),
    ("benign", "config_reload",       201),  # cold -> escalate -> benign stored
    ("attack", "resource_exhaustion", 102),
    ("benign", "normal_requests",     301),  # zero-signal -> ignore
    ("attack", "port_scan",           103),
    ("benign", "health_checks",       302),  # zero-signal -> ignore
    ("attack", "auth_bruteforce",     104),
    ("benign", "file_ops",            303),  # zero-signal -> ignore
    ("benign", "config_reload",       202),  # non-dup -> SUPPRESS from memory
    ("attack", "malformed_segfault",  105),  # repeat attack -> recognized, escalate
    ("benign", "config_reload",       203),  # non-dup -> SUPPRESS
    ("benign", "normal_requests",     304),  # ignore
    ("attack", "resource_exhaustion", 106),
    ("benign", "config_reload",       204),  # non-dup -> SUPPRESS
    ("benign", "health_checks",       305),  # ignore
    ("attack", "port_scan",           107),
    ("benign", "config_reload",       205),  # non-dup -> SUPPRESS
    ("benign", "file_ops",            306),  # ignore
    ("attack", "malformed_segfault",  108),  # recognized, escalate
    ("benign", "config_reload",       206),  # non-dup -> SUPPRESS
    ("benign", "normal_requests",     307),  # ignore
    ("attack", "auth_bruteforce",     109),
    ("benign", "health_checks",       308),  # ignore
    ("benign", "config_reload",       207),  # non-dup -> SUPPRESS
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
