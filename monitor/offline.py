"""Deterministic OFFLINE mirror of the gate + memory, for network-free replay.
Reproduces the exact Atlas aggregation math in Python (cosine score in Atlas space
=(1+cos)/2, same recency filter, same evidence floor, same group + decision rule,
same cheap-tier hard-signal override) so a recorded run replays identically with
NO calls to Atlas, Voyage, or the LLM. This is the deterministic fallback."""
import math
from monitor.cheap import has_hard_signal
from config.config import (RECENCY_WINDOW_SECS, MIN_EVIDENCE_SIM, MIN_MEAN_SIM,
                           SUPPRESS_RATIO, MIN_MEAN_CONF)

def _cos(a, b):
    d = sum(x*y for x, y in zip(a, b))
    na = math.sqrt(sum(x*x for x in a)); nb = math.sqrt(sum(y*y for y in b))
    return d/(na*nb) if na and nb else 0.0

def _atlas(c):   # match Atlas vectorSearchScore for cosine
    return (1 + c) / 2

class LocalMemory:
    def __init__(self): self.docs = []
    def wipe(self): self.docs = []
    def count(self): return len(self.docs)
    def write(self, embedding, verdict, confidence, ts):
        self.docs.append({"embedding": embedding, "verdict": verdict,
                          "confidence": confidence, "ts": int(ts)})

def local_decide(mem, query_embedding, now_ts, cheap_features):
    """Same output contract as monitor.gate.decide."""
    hard = has_hard_signal(cheap_features)

    since = int(now_ts) - RECENCY_WINDOW_SECS
    # $vectorSearch + $project(score) + $match(score>=floor), recency filtered
    ev = []
    for d in mem.docs:
        if d["ts"] < since:
            continue
        s = _atlas(_cos(query_embedding, d["embedding"]))
        if s >= MIN_EVIDENCE_SIM:
            ev.append((s, d))

    if hard:
        stats = _group(ev)
        stats.pop("decision", None)
        return {"decision": "escalate",
                "reason": "cheap-tier hard-signal override: hard-failure footprint is never suppressed",
                "neighbor_stats": stats}

    if not ev:
        return {"decision": "escalate",
                "reason": "no confident recent neighbors (cold start / below similarity floor)",
                "neighbor_stats": {"n": 0, "benign": 0, "malicious": 0, "mean_conf": None,
                                   "mean_score": None, "benign_ratio": None, "suppress_score": None}}

    stats = _group(ev)
    ratio = stats["benign_ratio"]
    suppress = (ratio >= SUPPRESS_RATIO and stats["mean_conf"] >= MIN_MEAN_CONF
                and stats["mean_score"] >= MIN_MEAN_SIM)
    decision = "suppress" if suppress else "escalate"
    reason = (f"{stats['benign']}/{stats['n']} neighbors benign (ratio {ratio}), "
              f"mean_conf {stats['mean_conf']}, mean_sim {stats['mean_score']}")
    return {"decision": decision, "reason": reason, "neighbor_stats": stats}

def _group(ev):
    n = len(ev)
    if n == 0:
        return {"n": 0, "benign": 0, "malicious": 0, "mean_conf": None,
                "mean_score": None, "top_score": None, "benign_ratio": None, "suppress_score": None}
    benign = sum(1 for s, d in ev if d["verdict"] == "benign")
    mal = sum(1 for s, d in ev if d["verdict"] == "malicious")
    mconf = sum(d["confidence"] for s, d in ev) / n
    mscore = sum(s for s, d in ev) / n
    top = max(s for s, d in ev)
    ratio = benign / n
    return {"n": n, "benign": benign, "malicious": mal,
            "mean_conf": round(mconf, 3), "mean_score": round(mscore, 3),
            "top_score": round(top, 3), "benign_ratio": round(ratio, 3),
            "suppress_score": round(ratio * mconf * mscore, 3)}
