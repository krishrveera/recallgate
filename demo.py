"""Scripted, deterministic demo runner.

Default is OFFLINE: it replays the recorded episode stream with NO network --
embeddings from embed_cache/, LLM verdicts from llm_cache/ (deterministic fallback
on miss), and the gate/memory decision computed by the local mirror in
monitor.offline (identical math to the Atlas aggregation). A dropped network or a
disabled LLM key cannot change the outcome.

  python demo.py            # offline deterministic replay (venue-safe)
  python demo.py --online   # same logic but allow network to (re)warm caches

Outputs: recall (hard gate), the expensive-call cost curve, and a PNG chart.
"""
import argparse, json, os, random
from monitor.cheap import anomaly_score, is_anomaly
from monitor.embed import embed
from monitor.llm import verdict as llm_verdict
from monitor.offline import LocalMemory, local_decide

STREAM = "data/footprints.jsonl"
TS_BASE = 1_700_000_000     # fixed synthetic clock -> deterministic recency window
TS_STEP = 1

def run(stream=STREAM, offline=True):
    fps = [json.loads(l) for l in open(stream)]
    vecs = embed([f["signature_text"] for f in fps], input_type="document", offline=offline)
    emb = {f["episode_id"]: v for f, v in zip(fps, vecs)}
    mem = LocalMemory()
    expensive = 0
    results = []
    for i, fp in enumerate(fps):
        eid, gt, cf = fp["episode_id"], fp["ground_truth_label"], fp["cheap_features"]
        now_ts = TS_BASE + i * TS_STEP
        cost, stats, reason = 0, None, ""
        if not is_anomaly(cf):
            decision, pred = "ignore", "benign"
            reason = "below cheap threshold"
        else:
            g = local_decide(mem, emb[eid], now_ts, cf)
            decision, stats, reason = g["decision"], g["neighbor_stats"], g["reason"]
            if decision == "suppress":
                pred = "benign"
            else:
                v = llm_verdict(fp["signature_text"],
                                context=f"cheap_score={anomaly_score(cf)}",
                                allow_network=not offline)
                cost = 1; expensive += 1; pred = v["verdict"]
                mem.write(emb[eid], pred, v["confidence"], now_ts)
        results.append({"i": i, "episode_id": eid, "truth": gt, "decision": decision,
                        "predicted": pred, "cost": cost, "cum": expensive,
                        "reason": reason, "neighbor_stats": stats})
    return results

def summarize(results, tag):
    n = len(results)
    attacks = [r for r in results if r["truth"] == "attack"]
    suppressed_attacks = [r for r in attacks if r["decision"] == "suppress"]
    escalated = [r for r in attacks if r["decision"] == "escalate"]
    recall = len(escalated) / len(attacks) if attacks else 0.0
    expensive = results[-1]["cum"] if results else 0
    saved = sum(1 for r in results if r["decision"] == "suppress")
    print(f"\n=== {tag} ===")
    for r in results:
        badge = {"ignore": "ignore   ", "suppress": "SUPPRESSED", "escalate": "ESCALATED "}[r["decision"]]
        print(f"  [{r['i']+1:2d}/{n}] {r['episode_id']:26s} truth={r['truth']:6s} "
              f"{badge} pred={r['predicted']:9s} cost={r['cost']} cum={r['cum']}")
    print(f"  expensive LLM calls          : {expensive}/{n}")
    print(f"  LLM calls saved by memory    : {saved}")
    print(f"  ATTACK RECALL (not suppressed): {len(escalated)}/{len(attacks)} = {recall:.2f}")
    assert not suppressed_attacks, f"RECALL FAIL: attacks suppressed: {[r['episode_id'] for r in suppressed_attacks]}"
    return recall, [r["cost"] for r in results], [r["cum"] for r in results]

def chart(results, path="data/cost_curve.png"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    n = len(results)
    costs = [r["cost"] for r in results]
    cum = [r["cum"] for r in results]
    # rolling expensive-calls-per-episode (window 6)
    w = 6
    roll = [sum(costs[max(0, k-w+1):k+1]) / min(k+1, w) for k in range(n)]
    x = list(range(1, n+1))
    fig, ax1 = plt.subplots(figsize=(9, 4.5))
    ax1.plot(x, roll, color="#c0392b", lw=2.4, marker="o", ms=4,
             label=f"expensive LLM calls / episode (rolling {w})")
    ax1.fill_between(x, roll, color="#c0392b", alpha=0.08)
    ax1.set_xlabel("episode"); ax1.set_ylabel("LLM calls per episode", color="#c0392b")
    ax1.set_ylim(0, 1.05); ax1.tick_params(axis="y", labelcolor="#c0392b")
    ax2 = ax1.twinx()
    ax2.plot(x, cum, color="#2c3e50", lw=1.6, ls="--", label="cumulative LLM calls")
    ax2.set_ylabel("cumulative LLM calls", color="#2c3e50")
    ax2.tick_params(axis="y", labelcolor="#2c3e50")
    ax1.set_title("On-demand monitor: expensive-call rate bends toward zero as memory fills")
    l1, la1 = ax1.get_legend_handles_labels(); l2, la2 = ax2.get_legend_handles_labels()
    ax1.legend(l1+l2, la1+la2, loc="center right", fontsize=8, framealpha=0.9)
    fig.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)
    print(f"  cost chart written: {path}")

# ======================================================================
# LIVE mode: real Atlas $vectorSearch + real memory, embeddings/LLM cache-or-live.
# The offline path above is untouched and remains the fallback.
# ======================================================================
HELDOUT = "data/heldout.jsonl"
INTER_EP_SLEEP = 4.0   # let Atlas Search index freshly-written incidents

def _live_episode(fp, vec, now_ts, print_pipeline=False):
    """Run ONE footprint through the real live pipeline. Returns (decision, pred,
    stats, reason, cost). Writes to live Atlas memory on escalate."""
    from monitor.gate import decide
    from monitor.llm import verdict as llm_verdict
    from memory.store import write_incident
    cf = fp["cheap_features"]
    if not is_anomaly(cf):
        return "ignore", "benign", None, "below cheap threshold", 0
    g = decide(vec, now_ts, cheap_features=cf, print_pipeline=print_pipeline)
    if g["decision"] == "suppress":
        return "suppress", "benign", g["neighbor_stats"], g["reason"], 0
    v = llm_verdict(fp["signature_text"], context=f"cheap_score={anomaly_score(cf)}",
                    allow_network=True)   # cache-or-live
    write_incident(fp["episode_id"], fp["signature_text"], vec, v["verdict"],
                   v["confidence"], fp["ground_truth_label"], cf, now_ts)
    return "escalate", v["verdict"], g["neighbor_stats"], v["reasoning"], 1

def live_stream(stream=STREAM, shuffle_seed=None, wipe_first=True, tag="LIVE stream"):
    import time
    from memory.store import wipe as mem_wipe
    fps = [json.loads(l) for l in open(stream)]
    if shuffle_seed is not None:
        random.Random(shuffle_seed).shuffle(fps)
        tag += f" (shuffled seed={shuffle_seed})"
    vecs = embed([f["signature_text"] for f in fps], input_type="document")  # cache-or-live
    emb = {f["episode_id"]: v for f, v in zip(fps, vecs)}
    if wipe_first:
        mem_wipe()
    print(f"\n=== {tag} -- real Atlas $vectorSearch + live memory ===")
    expensive = 0; results = []
    for i, fp in enumerate(fps):
        eid = fp["episode_id"]
        decision, pred, stats, reason, cost = _live_episode(fp, emb[eid], int(time.time()))
        expensive += cost
        results.append({"episode_id": eid, "truth": fp["ground_truth_label"],
                        "decision": decision, "predicted": pred, "cost": cost, "cum": expensive})
        badge = {"ignore": "ignore   ", "suppress": "SUPPRESSED", "escalate": "ESCALATED "}[decision]
        print(f"  [{i+1:2d}/{len(fps)}] {eid:26s} truth={fp['ground_truth_label']:6s} "
              f"{badge} pred={pred:9s} cost={cost} cum={expensive}")
        time.sleep(INTER_EP_SLEEP)
    attacks = [r for r in results if r["truth"] == "attack"]
    supp = [r for r in attacks if r["decision"] == "suppress"]
    recall = 1 - len(supp)/len(attacks) if attacks else 1.0
    saved = sum(1 for r in results if r["decision"] == "suppress")
    print(f"  expensive calls={expensive}  suppressions={saved}  "
          f"ATTACK RECALL={len(attacks)-len(supp)}/{len(attacks)}={recall:.2f}")
    assert not supp, f"RECALL FAIL: {[r['episode_id'] for r in supp]}"
    return results

def live_heldout(train=STREAM, held=HELDOUT):
    import time
    print("[.] LIVE mode: warming Atlas memory with the training stream ...")
    live_stream(train, wipe_first=True, tag="warm-up (training stream)")
    print("\n[.] waiting for final writes to index ..."); time.sleep(8)

    held_fps = [json.loads(l) for l in open(held)]
    print(f"\n=== HELD-OUT (never seen, NOT pre-cached) -- {len(held_fps)} footprints, live ===")
    vecs = embed([f["signature_text"] for f in held_fps], input_type="document")  # live embed
    results = []
    for i, fp in enumerate(held_fps):
        eid = fp["episode_id"]
        decision, pred, stats, reason, cost = _live_episode(
            fp, vecs[i], int(time.time()), print_pipeline=(i == 0))
        results.append({"episode_id": eid, "truth": fp["ground_truth_label"],
                        "decision": decision, "predicted": pred})
        badge = {"ignore": "ignore", "suppress": "SUPPRESSED", "escalate": "ESCALATED"}[decision]
        print(f"\n  {eid}  truth={fp['ground_truth_label']}  -> {badge}  pred={pred}")
        print(f"    reason        : {reason}")
        print(f"    neighbor_stats: {json.dumps(stats)}")
        time.sleep(INTER_EP_SLEEP)
    attacks = [r for r in results if r["truth"] == "attack"]
    supp = [r for r in attacks if r["decision"] == "suppress"]
    print(f"\nHELD-OUT SUMMARY: {len(attacks)} attacks, {len(supp)} suppressed, "
          f"ATTACK RECALL={len(attacks)-len(supp)}/{len(attacks)}="
          f"{1-len(supp)/len(attacks) if attacks else 1.0:.2f}")
    assert not supp, f"RECALL FAIL on held-out: {[r['episode_id'] for r in supp]}"

def live_footprint(path, warm=True):
    """Feed one supplied footprint to the live gate against current memory."""
    import time
    if warm:
        live_stream(STREAM, wipe_first=True, tag="warm-up (training stream)")
        time.sleep(8)
    fp = json.load(open(path)) if path.endswith(".json") else json.loads(open(path).readline())
    vec = embed([fp["signature_text"]], input_type="document")[0]  # live embed
    decision, pred, stats, reason, cost = _live_episode(fp, vec, int(time.time()), print_pipeline=True)
    print(f"\nSUPPLIED FOOTPRINT: {fp.get('episode_id','(adhoc)')}")
    print(f"  decision      : {decision.upper()}  pred={pred}")
    print(f"  reason        : {reason}")
    print(f"  neighbor_stats: {json.dumps(stats)}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--online", action="store_true", help="offline logic but allow network to warm caches")
    ap.add_argument("--offline", action="store_true", help="fully offline deterministic replay (default)")
    ap.add_argument("--live", action="store_true", help="live pipeline: real Atlas + memory, cache-or-live embed/LLM")
    ap.add_argument("--shuffle", type=int, default=None, help="run the stream in a shuffled order (live)")
    ap.add_argument("--footprint", default=None, help="feed one supplied footprint to the live gate")
    ap.add_argument("--stream", default=STREAM)
    args = ap.parse_args()

    if args.footprint:
        live_footprint(args.footprint); return
    if args.live and args.shuffle is not None:
        live_stream(args.stream, shuffle_seed=args.shuffle); return
    if args.live:
        live_heldout(args.stream); return

    # ---- offline default (unchanged) ----
    offline = not args.online
    mode = "OFFLINE replay (no network)" if offline else "ONLINE (network allowed)"
    print(f"[.] scripted demo -- {mode}")
    results = run(args.stream, offline=offline)
    recall, costs, cum = summarize(results, mode)
    chart(results)
    json.dump(results, open("data/demo_results.json", "w"), indent=2)
    print(f"\n[OK] demo complete. recall={recall:.2f}  expensive_calls={cum[-1]}  cost_series={costs}")

if __name__ == "__main__":
    main()
