"""Separation-gap analysis for the current stream.

Only footprints that cross the cheap threshold ever reach the gate and can enter
memory. So the operationally-decisive gap is measured over GATE-REACHING families.
The recall-critical number is: max similarity between a MEMORY-ELIGIBLE BENIGN
footprint and any ATTACK footprint -- if that stays below the evidence floor, no
attack can ever land in a benign-dominated evidence set, so recall is protected."""
import json, itertools, math
from monitor.embed import embed
from monitor.cheap import is_anomaly
from config.config import MIN_EVIDENCE_SIM

def cos(a, b):
    d = sum(x*y for x, y in zip(a, b))
    na = math.sqrt(sum(x*x for x in a)); nb = math.sqrt(sum(y*y for y in b))
    return d/(na*nb) if na and nb else 0.0

def fam(eid): return eid.split("-", 1)[1]

def stats(pairs):
    xs = [p[0] for p in pairs]
    return (len(xs), sum(xs)/len(xs), min(xs), max(xs)) if xs else (0, 0, 0, 0)

def report(rows, vecs, idxs, floor, title):
    same, cross, crit = [], [], []
    for i, j in itertools.combinations(idxs, 2):
        s = cos(vecs[i], vecs[j]); fi, fj = fam(rows[i]["episode_id"]), fam(rows[j]["episode_id"])
        li, lj = rows[i]["ground_truth_label"], rows[j]["ground_truth_label"]
        if fi == fj: same.append((s,))
        else:
            cross.append((s,))
            if li != lj: crit.append((s, fi if li=="benign" else fj, fj if lj=="attack" else fi))
    A = lambda c: (1 + c) / 2   # raw cosine -> Atlas vectorSearchScore space
    ns, ms, mns, mxs = stats(same); nc, mc, mnc, mxc = stats(cross)
    print(f"--- {title} ---")
    print(f"  (values shown in ATLAS score space =(1+cosine)/2, the space the gate thresholds)")
    print(f"  SAME-family : n={ns:3d} mean={A(ms):.3f} min={A(mns):.3f} max={A(mxs):.3f}  (want min > {floor})")
    print(f"  CROSS-family: n={nc:3d} mean={A(mc):.3f} min={A(mnc):.3f} max={A(mxc):.3f}  (want max < {floor})")
    if crit:
        crit.sort(reverse=True)
        worst = A(crit[0][0])
        print(f"  RECALL-CRITICAL benign-vs-attack max = {worst:.3f}  "
              f"({'SAFE' if worst < floor else 'DANGER'} vs floor {floor})")
        for mx, b, a in crit[:5]:
            print(f"     {b:18s}(benign) vs {a:18s}(attack)  {A(mx):.3f}"
                  f"{'  <-- ABOVE FLOOR' if A(mx)>=floor else ''}")
    if same and crit:
        print(f"  GAP (same-family min {A(mns):.3f}) - (benign-vs-attack max {A(crit[0][0]):.3f}) "
              f"= {A(mns)-A(crit[0][0]):+.3f}; floor {floor} between them? "
              f"{'YES, clean' if A(crit[0][0]) < floor <= A(mns) else 'NO'}")
    print()

def main():
    rows = [json.loads(l) for l in open("data/footprints.jsonl")]
    vecs = embed([r["signature_text"] for r in rows], input_type="document")
    floor = MIN_EVIDENCE_SIM
    all_idx = list(range(len(rows)))
    gate_idx = [i for i in all_idx if is_anomaly(rows[i]["cheap_features"])]

    print(f"evidence floor = {floor}\n")
    report(rows, vecs, all_idx, floor, "ALL families (includes zero-signal benigns that never reach the gate)")
    report(rows, vecs, gate_idx, floor,
           "GATE-REACHING families only (the footprints the gate actually compares & stores)")

    # explicit: memory-eligible benign == anomalous benign (only config_reload here)
    mem_benign = sorted({fam(rows[i]["episode_id"]) for i in gate_idx
                         if rows[i]["ground_truth_label"]=="benign"})
    print(f"memory-eligible benign families (anomalous benigns that get stored): {mem_benign}")

if __name__ == "__main__":
    main()
