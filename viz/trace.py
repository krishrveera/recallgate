"""Instrument the real pipeline into per-episode stage records for the glass-box UI.
Both live (real Atlas + Voyage + LLM) and offline (local mirror + caches) yield the
SAME record shape, so the page is agnostic to which drove it."""
import time, json
from monitor.cheap import anomaly_score, is_anomaly, has_hard_signal, _ALLOWED
from monitor.embed import embed
from monitor.llm import verdict as llm_verdict
from config.config import (ANOMALY_THRESHOLD, MIN_EVIDENCE_SIM, MIN_MEAN_SIM,
                           MIN_MEAN_CONF, SUPPRESS_RATIO, NUM_CANDIDATES, GATE_LIMIT,
                           RECENCY_WINDOW_SECS, VECTOR_INDEX)

STREAM = "data/footprints.jsonl"
HARD_KEYS = ["oom_kills", "nonzero_exit_count", "conn_refused_count", "distinct_error_types"]
HARD_NAME = {"oom_kills": "OOM-kill", "nonzero_exit_count": "nonzero exit code",
             "conn_refused_count": "refused connections", "distinct_error_types": "error signatures"}

def _family(eid): return eid.split("-", 1)[1] if "-" in eid else eid

def _cheap_detail(cf):
    contrib = {k: cf.get(k, 0) for k in _ALLOWED if cf.get(k, 0)}
    return {"score": anomaly_score(cf), "threshold": ANOMALY_THRESHOLD,
            "passed": is_anomaly(cf), "nonzero_features": contrib}

def _override_detail(cf):
    sigs = [HARD_NAME[k] for k in HARD_KEYS if cf.get(k, 0)]
    return {"fires": bool(sigs), "signals": sigs}

def _pipeline_log():
    return [
        f"$vectorSearch  index={VECTOR_INDEX} path=embedding numCandidates={NUM_CANDIDATES} "
        f"limit={GATE_LIMIT} filter: ts >= now-{RECENCY_WINDOW_SECS}s",
        "$project       verdict, confidence, ts, score={$meta vectorSearchScore}  (ground_truth NOT projected)",
        f"$match         score >= {MIN_EVIDENCE_SIM}   (evidence floor: genuine near-neighbours only)",
        "$group         n, benign, malicious, mean_conf, mean_score",
        f"$project       benign_ratio, suppress_score, decision "
        f"(suppress iff ratio>={SUPPRESS_RATIO} & mean_conf>={MIN_MEAN_CONF} & mean_sim>={MIN_MEAN_SIM})",
    ]

def _record(i, fp, cheap, override, neighbors, stats, decision, reason, llm, cost, cum, saved, recall):
    eid = fp["episode_id"]
    logs = [f"footprint arrived: family={_family(eid)} label={fp['ground_truth_label']}",
            f"cheap gate: score={cheap['score']} threshold={cheap['threshold']} -> "
            + ("PASSED to gate" if cheap["passed"] else "IGNORED (all-quiet)")]
    if cheap["passed"]:
        logs.append("hard-signal override: " + ("FIRED (" + ", ".join(override["signals"]) + ")"
                                                 if override["fires"] else "not applicable"))
        logs.append("Atlas compound aggregation (server-side decision):")
        logs += ["   " + s for s in _pipeline_log()]
        logs.append(f"retrieved {len(neighbors)} neighbour(s) within recency window:")
        for nb in neighbors:
            ev = "evidence" if nb["score"] >= MIN_EVIDENCE_SIM else "below floor"
            logs.append(f"   {nb.get('episode_id','?'):26s} verdict={nb['verdict']:9s} "
                        f"score={nb['score']:.3f}  [{ev}]")
        if stats and stats.get("n"):
            logs.append(f"neighbour_stats over evidence: n={stats['n']} benign={stats['benign']} "
                        f"malicious={stats['malicious']} benign_ratio={stats['benign_ratio']} "
                        f"mean_conf={stats['mean_conf']} mean_sim={stats['mean_score']}")
        else:
            logs.append("neighbour_stats: no neighbour cleared the evidence floor")
    logs.append(f"DECISION: {decision.upper()} -- {reason}")
    if llm:
        logs.append(f"LLM verdict: {llm['verdict']} (conf {llm['confidence']}) -- {llm['reasoning']}")
        logs.append("incident written to memory")
    return {
        "index": i, "episode_id": eid, "family": _family(eid), "label": fp["ground_truth_label"],
        "signature_text": fp["signature_text"], "cheap_features": {k: fp["cheap_features"].get(k, 0) for k in _ALLOWED},
        "cheap": cheap, "override": override,
        "atlas": {"ran": cheap["passed"], "neighbors": neighbors, "stats": stats,
                  "floor": MIN_EVIDENCE_SIM},
        "decision": decision, "reason": reason, "llm": llm,
        "cost": cost, "cum_cost": cum, "saved": saved, "recall": recall,
        "logs": logs,
    }

# ---------------- LIVE / FRESH ----------------
# live : real Atlas + a real LLM call on every escalation (embedding cache for speed)
# fresh: same, but also bypasses the embedding cache (nothing read from any cache)
def live_records(stream=STREAM, inter_sleep=4.0, fresh=False):
    from monitor.gate import decide, neighbors_debug
    from memory.store import write_incident, wipe
    fps = [json.loads(l) for l in open(stream)]
    vecs = embed([f["signature_text"] for f in fps], input_type="document", no_cache=fresh)
    emb = {f["episode_id"]: v for f, v in zip(fps, vecs)}
    wipe()
    expensive = saved = atk = atk_esc = 0
    for i, fp in enumerate(fps):
        eid, cf = fp["episode_id"], fp["cheap_features"]
        now_ts = int(time.time())
        cheap = _cheap_detail(cf); override = _override_detail(cf)
        neighbors, stats, decision, reason, llm, cost = [], None, "ignore", "below cheap threshold", None, 0
        if cheap["passed"]:
            neighbors = neighbors_debug(emb[eid], now_ts, limit=GATE_LIMIT)
            g = decide(emb[eid], now_ts, cheap_features=cf, print_pipeline=False)
            decision, stats, reason = g["decision"], g["neighbor_stats"], g["reason"]
            if decision == "escalate":
                _t = time.time()
                # live = a REAL call every escalation, persisting nothing (fresh each run)
                v = llm_verdict(fp["signature_text"], context=f"cheap_score={cheap['score']}",
                                allow_network=True, no_cache=True, no_write=True)
                _ms = int((time.time() - _t) * 1000)
                cost = 1; expensive += 1
                llm = {"verdict": v["verdict"], "confidence": v["confidence"], "reasoning": v["reasoning"],
                       "cached": bool(v.get("cached")), "source": v.get("source", "llm"), "ms": _ms}
                write_incident(eid, fp["signature_text"], emb[eid], v["verdict"],
                               v["confidence"], fp["ground_truth_label"], cf, now_ts)
            else:
                saved += 1
        if fp["ground_truth_label"] == "attack":
            atk += 1; atk_esc += (decision == "escalate")
        recall = round(atk_esc/atk, 3) if atk else 1.0
        yield _record(i, fp, cheap, override, neighbors, stats, decision, reason, llm,
                      cost, expensive, saved, recall)
        time.sleep(inter_sleep)

# ---------------- OFFLINE ----------------
def offline_records(stream=STREAM, inter_sleep=0.6):
    from monitor.offline import LocalMemory, local_decide, local_neighbors
    TS = 1_700_000_000
    fps = [json.loads(l) for l in open(stream)]
    vecs = embed([f["signature_text"] for f in fps], input_type="document", offline=True)
    emb = {f["episode_id"]: v for f, v in zip(fps, vecs)}
    mem = LocalMemory()
    expensive = saved = atk = atk_esc = 0
    for i, fp in enumerate(fps):
        eid, cf = fp["episode_id"], fp["cheap_features"]
        now_ts = TS + i
        cheap = _cheap_detail(cf); override = _override_detail(cf)
        neighbors, stats, decision, reason, llm, cost = [], None, "ignore", "below cheap threshold", None, 0
        if cheap["passed"]:
            neighbors = local_neighbors(mem, emb[eid], now_ts, limit=GATE_LIMIT)
            g = local_decide(mem, emb[eid], now_ts, cf)
            decision, stats, reason = g["decision"], g["neighbor_stats"], g["reason"]
            if decision == "escalate":
                v = llm_verdict(fp["signature_text"], context=f"cheap_score={cheap['score']}", allow_network=False)
                cost = 1; expensive += 1
                llm = {"verdict": v["verdict"], "confidence": v["confidence"], "reasoning": v["reasoning"],
                       "cached": bool(v.get("cached")), "source": v.get("source", "llm"), "ms": 0}
                mem.write(emb[eid], v["verdict"], v["confidence"], now_ts, episode_id=eid)
            else:
                saved += 1
        if fp["ground_truth_label"] == "attack":
            atk += 1; atk_esc += (decision == "escalate")
        recall = round(atk_esc/atk, 3) if atk else 1.0
        yield _record(i, fp, cheap, override, neighbors, stats, decision, reason, llm,
                      cost, expensive, saved, recall)
        time.sleep(inter_sleep)
