"""Phase 3: run the longer stream. Enforce recall as a HARD GATE and print the
expensive-call cost trend. If any ATTACK is ever suppressed, stop and dump the case."""
import json, time, sys
from monitor.cheap import anomaly_score, is_anomaly
from monitor.gate import decide, neighbors_debug
from monitor.llm import verdict as llm_verdict
from monitor.embed import embed
from memory.store import write_incident, wipe, count

STREAM = "data/footprints.jsonl"
RESULTS = "data/phase3_results.jsonl"
INTER_EP_SLEEP = 4.0

def main():
    fps = [json.loads(l) for l in open(STREAM)]
    print(f"[.] wiping memory; embedding {len(fps)} signatures in one batch ...")
    wipe()
    vecs = embed([f["signature_text"] for f in fps], input_type="document")
    emb = {f["episode_id"]: v for f, v in zip(fps, vecs)}

    expensive = 0
    results = []
    for i, fp in enumerate(fps):
        eid, gt, cf = fp["episode_id"], fp["ground_truth_label"], fp["cheap_features"]
        now_ts = int(time.time())
        cost, stats = 0, None
        if not is_anomaly(cf):
            decision, pred = "ignore", "benign"
        else:
            g = decide(emb[eid], now_ts, cheap_features=cf, print_pipeline=False)
            decision, stats = g["decision"], g["neighbor_stats"]
            if decision == "suppress":
                pred = "benign"
            else:
                v = llm_verdict(fp["signature_text"], context=f"cheap_score={anomaly_score(cf)}")
                cost = 1; expensive += 1; pred = v["verdict"]
                write_incident(eid, fp["signature_text"], emb[eid], pred,
                               v["confidence"], gt, cf, now_ts)
        results.append({"i": i, "episode_id": eid, "truth": gt, "decision": decision,
                        "predicted": pred, "cost": cost, "cum": expensive,
                        "neighbor_stats": stats})
        print(f"  [{i+1:2d}/{len(fps)}] {eid:26s} truth={gt:6s} "
              f"{decision:9s} pred={pred:9s} cost={cost} cum={expensive}")
        time.sleep(INTER_EP_SLEEP)

    with open(RESULTS, "w") as f:
        for r in results: f.write(json.dumps(r) + "\n")

    # ---------- RECALL HARD GATE ----------
    # Recall (per spec) = attacks that were NOT suppressed, i.e. still reached the
    # expensive tier. Detection accuracy (was the LLM verdict correct) is explicitly
    # NOT the headline and is reported separately below.
    attacks = [r for r in results if r["truth"] == "attack"]
    suppressed_attacks = [r for r in attacks if r["decision"] == "suppress"]
    escalated = [r for r in attacks if r["decision"] == "escalate"]
    recall = len(escalated) / len(attacks) if attacks else 0.0

    if suppressed_attacks:
        print("\n" + "!"*70)
        print("RECALL GATE FAILED -- an attack was suppressed. STOPPING.")
        print("!"*70)
        for r in suppressed_attacks:
            fp = next(f for f in fps if f["episode_id"] == r["episode_id"])
            print(f"\nSUPPRESSED ATTACK: {r['episode_id']}")
            print(f"  footprint: {fp['signature_text']}")
            print(f"  gate neighbor_stats: {json.dumps(r['neighbor_stats'])}")
            print(f"  neighbors that caused it (verdict, similarity):")
            for nb in neighbors_debug(emb[r["episode_id"]], int(time.time())):
                print(f"     {nb.get('episode_id','?'):26s} verdict={nb.get('verdict')} "
                      f"score={nb.get('score'):.3f}")
        sys.exit(2)

    # ---------- COST TREND ----------
    n = len(results)
    half = n // 2
    rate1 = sum(r["cost"] for r in results[:half]) / half
    rate2 = sum(r["cost"] for r in results[half:]) / (n - half)
    print("\n" + "="*70)
    print("PHASE 3 SUMMARY")
    print("="*70)
    llm_correct = [r for r in escalated if r["predicted"] == "malicious"]
    print(f"episodes                     : {n}")
    print(f"total expensive LLM calls    : {expensive}")
    print(f"ATTACK RECALL (not suppressed): {len(escalated)}/{len(attacks)} = {recall:.2f}   [HARD GATE]")
    print(f"  -> attacks suppressed       : {len(suppressed_attacks)}  (must be 0)")
    print(f"expensive-calls-per-episode  : first half={rate1:.2f}  second half={rate2:.2f}  "
          f"({'DOWN' if rate2 < rate1 else 'not down'})")
    print(f"(secondary, NOT the headline) LLM verdict=malicious on escalated attacks: "
          f"{len(llm_correct)}/{len(escalated)}  -- ambiguous OOM/scan footprints can read benign "
          f"from Docker-level signal alone; the override keeps them escalated regardless")
    # rolling window rate to show the trend bending
    w = 6
    print(f"\nrolling expensive-rate (window={w}):")
    for k in range(0, n - w + 1, 2):
        window = results[k:k+w]
        rate = sum(r["cost"] for r in window) / w
        bar = "#" * int(rate * 20)
        print(f"  ep{k:2d}-{k+w-1:2d}: {rate:.2f} {bar}")
    print(f"\nGREEN LIGHTS: cost trend down = {rate2 < rate1};  recall == 1.00 = {recall==1.0}")

if __name__ == "__main__":
    main()
