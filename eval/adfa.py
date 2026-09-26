"""ADFA-LD replay fallback: drive the SAME monitor core (embed -> gate/memory ->
LLM) with real labeled syscall traces instead of docker footprints.

Each trace becomes a footprint whose signature_text is an observation-only
rendering of the real syscall sequence. The docker cheap-tier heuristic does not
apply to syscalls, so every trace is sent to the gate; memory still suppresses
recurring near-duplicate traces and escalates novel/attack ones. Recall =
attack traces not suppressed. Uses the deterministic offline mirror for the
decision so it runs the same way with or without Atlas."""
import os, json, glob, random, collections
from monitor.embed import embed
from monitor.llm import verdict as llm_verdict
from monitor.offline import LocalMemory, local_decide

BASE = "data/adfa_raw/ADFA-LD"
TS_BASE = 1_700_000_000

# a few well-known syscall numbers for readable rendering (Linux i386, ADFA-LD)
NAMES = {1:"exit",2:"fork",3:"read",4:"write",5:"open",6:"close",11:"execve",
         45:"brk",63:"dup2",90:"mmap",91:"munmap",102:"socketcall",120:"clone",
         122:"uname",125:"mprotect",174:"rt_sigaction",175:"rt_sigprocmask",
         192:"mmap2",195:"stat64",197:"fstat64",221:"fcntl64",240:"futex",252:"exit_group"}

def _name(s):
    return NAMES.get(int(s), f"sys{s}")

def render(trace):
    """Observation-only NL rendering of a real syscall trace."""
    L = len(trace)
    cnt = collections.Counter(trace)
    top = cnt.most_common(4)
    distinct = len(cnt)
    top_txt = ", ".join(f"{_name(s)}({s}) x{c}" for s, c in top)
    head = " ".join(_name(s) for s in trace[:16])
    tail = " ".join(_name(s) for s in trace[-8:])
    return (f"System-call trace of length {L} with {distinct} distinct syscalls. "
            f"Most frequent: {top_txt}. The trace opens with: {head}. "
            f"It ends with: {tail}.")

def load_trace(path):
    with open(path) as f:
        return [int(x) for x in f.read().split()]

def build_stream(n_normal=14, n_attack=10, seed=7):
    rnd = random.Random(seed)
    normal = sorted(glob.glob(f"{BASE}/Training_Data_Master/*.txt")) + \
             sorted(glob.glob(f"{BASE}/Validation_Data_Master/*.txt"))
    attacks = sorted(glob.glob(f"{BASE}/Attack_Data_Master/*/*.txt"))
    norm_sel = rnd.sample(normal, n_normal)
    atk_sel = rnd.sample(attacks, n_attack)
    items = [(p, "benign") for p in norm_sel] + [(p, "attack") for p in atk_sel]
    rnd.shuffle(items)
    fps = []
    for i, (p, label) in enumerate(items):
        tr = load_trace(p)
        atype = os.path.basename(os.path.dirname(p)) if label == "attack" else "normal"
        fps.append({"episode_id": f"adfa{i:02d}-{atype}",
                    "ground_truth_label": label,
                    "signature_text": render(tr),
                    "cheap_features": {"restart_count":0,"oom_kills":0,"nonzero_exit_count":0,
                                       "failure_rate":0.0,"distinct_error_types":0,"cpu_spike":0,
                                       "mem_spike":0,"conn_refused_count":0},  # no docker signal
                    "trace_len": len(tr), "src": p})
    return fps

def main():
    fps = build_stream()
    os.makedirs("data", exist_ok=True)
    with open("data/adfa_stream.jsonl", "w") as f:
        for fp in fps: f.write(json.dumps(fp) + "\n")
    print(f"[.] built ADFA-LD stream: {len(fps)} traces "
          f"({sum(1 for f in fps if f['ground_truth_label']=='attack')} attack, "
          f"{sum(1 for f in fps if f['ground_truth_label']=='benign')} normal)")

    vecs = embed([f["signature_text"] for f in fps], input_type="document")
    emb = {f["episode_id"]: v for f, v in zip(fps, vecs)}
    mem = LocalMemory()
    expensive = 0; results = []
    for i, fp in enumerate(fps):
        eid, gt, cf = fp["episode_id"], fp["ground_truth_label"], fp["cheap_features"]
        now_ts = TS_BASE + i
        g = local_decide(mem, emb[eid], now_ts, cf)  # every trace goes to the gate
        cost = 0
        if g["decision"] == "suppress":
            pred = "benign"
        else:
            v = llm_verdict(fp["signature_text"], context=f"data=syscall_trace len={fp['trace_len']}")
            cost = 1; expensive += 1; pred = v["verdict"]
            mem.write(emb[eid], pred, v["confidence"], now_ts)
        results.append({"i": i, "episode_id": eid, "truth": gt,
                        "decision": g["decision"], "predicted": pred, "cost": cost, "cum": expensive})
        print(f"  [{i+1:2d}/{len(fps)}] {eid:28s} truth={gt:6s} {g['decision']:9s} "
              f"pred={pred:9s} cost={cost} cum={expensive}")

    attacks = [r for r in results if r["truth"] == "attack"]
    supp_atk = [r for r in attacks if r["decision"] == "suppress"]
    recall = 1 - len(supp_atk)/len(attacks) if attacks else 0.0
    json.dump(results, open("data/adfa_results.json", "w"), indent=2)
    print(f"\nADFA-LD replay: {len(fps)} traces, expensive calls={expensive}, "
          f"attacks suppressed={len(supp_atk)}, ATTACK RECALL={recall:.2f}")
    if supp_atk:
        print("  suppressed attacks (recall leak):", [r["episode_id"] for r in supp_atk])

if __name__ == "__main__":
    main()
