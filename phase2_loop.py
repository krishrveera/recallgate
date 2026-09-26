"""Phase 2 full loop on the captured stream:
   cheap gate (numeric only) -> Atlas escalation aggregation -> LLM verdict
   -> write to memory -> cost metric.

Firewall recap: cheap tier reads only cheap_features; LLM tier reads signature_text;
gate never reads ground_truth_label (used here only to score recall at the end)."""
import json, time, sys
from monitor.cheap import anomaly_score, is_anomaly
from monitor.gate import decide
from monitor.llm import verdict as llm_verdict
from monitor.embed import embed
from memory.store import write_incident, wipe, count

STREAM = "data/footprints.jsonl"
RESULTS = "data/phase2_results.jsonl"
INTER_EP_SLEEP = 4.0   # let Atlas Search index freshly-written incidents

def main():
    footprints = [json.loads(l) for l in open(STREAM)]
    print(f"[.] wiping incident memory for a fresh session ...")
    wipe()

    # Batch-embed every signature_text in ONE Voyage request (respects free-tier RPM).
    print(f"[.] embedding {len(footprints)} signature_texts in one batch ...")
    vecs = embed([f["signature_text"] for f in footprints], input_type="document")
    emb = {f["episode_id"]: v for f, v in zip(footprints, vecs)}

    expensive_calls = 0
    cost_series, results = [], []
    printed_pipeline = False

    for i, fp in enumerate(footprints):
        eid = fp["episode_id"]; gt = fp["ground_truth_label"]; cf = fp["cheap_features"]
        now_ts = int(time.time())
        score = anomaly_score(cf)
        print(f"\n=== [{i+1}/{len(footprints)}] {eid}  (truth={gt}) ===")
        print(f"  cheap tier: anomaly_score={score}  anomaly={is_anomaly(cf)}  (numeric features only)")

        cost = 0
        if not is_anomaly(cf):
            decision, pred, src = "ignore", "benign", "cheap"
            reason = f"cheap score {score} < threshold; ignored (no gate, no LLM)"
            stats = None
            print(f"  -> IGNORE ({reason})")
        else:
            # print the full pipeline the first time and on the repeated-attack pass
            show = (not printed_pipeline) or (eid == "ep09-malformed_segfault")
            g = decide(emb[eid], now_ts, print_pipeline=show)
            printed_pipeline = True
            decision = g["decision"]; stats = g["neighbor_stats"]
            print(f"  gate neighbor_stats: {json.dumps(stats)}")
            print(f"  gate decision: {decision.upper()} -- {g['reason']}")

            if decision == "suppress":
                pred, src = "benign", "memory"
                reason = g["reason"]
                print(f"  -> SUPPRESS: resolved benign from memory, NO expensive call")
            else:
                v = llm_verdict(fp["signature_text"],
                                context=f"episode {eid}; cheap_score={score}")
                cost = 1; expensive_calls += 1
                pred = v["verdict"]; src = "llm(" + v.get("source","?") + ("/cached" if v.get("cached") else "") + ")"
                reason = v["reasoning"]
                print(f"  -> ESCALATE: LLM verdict={pred} conf={v['confidence']} src={src}")
                # every escalation writes the incident to memory
                write_incident(eid, fp["signature_text"], emb[eid], pred,
                               v["confidence"], gt, cf, now_ts)
                print(f"     wrote incident to memory (now {count()} incidents)")

        cost_series.append(cost)
        results.append({"episode_id": eid, "truth": gt, "decision": decision,
                        "predicted": pred, "source": src, "cost": cost,
                        "cum_cost": expensive_calls, "cheap_score": score,
                        "neighbor_stats": stats, "reason": reason})
        print(f"  cost={cost}  cumulative_expensive_calls={expensive_calls}")
        time.sleep(INTER_EP_SLEEP)

    with open(RESULTS, "w") as f:
        for r in results: f.write(json.dumps(r) + "\n")

    # ---- summary ----
    attacks = [r for r in results if r["truth"] == "attack"]
    caught = [r for r in attacks if r["predicted"] == "malicious"]
    recall = len(caught) / len(attacks) if attacks else 0.0
    print("\n" + "=" * 70)
    print("PHASE 2 SUMMARY")
    print("=" * 70)
    print(f"episodes            : {len(results)}")
    print(f"expensive LLM calls : {expensive_calls}  (of {len(results)} episodes)")
    print(f"per-episode cost    : {cost_series}")
    print(f"attack recall       : {len(caught)}/{len(attacks)} = {recall:.2f}")
    print(f"\nper-episode decisions:")
    for r in results:
        print(f"  {r['episode_id']:26s} truth={r['truth']:6s} "
              f"decision={r['decision']:9s} pred={r['predicted']:9s} "
              f"cost={r['cost']} src={r['source']}")

if __name__ == "__main__":
    main()
