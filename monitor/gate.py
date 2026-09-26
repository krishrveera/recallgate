"""Escalate-or-suppress gate.

The decision is computed in ONE compound Atlas aggregation, entirely server-side:
  1. $vectorSearch on the signature_text embedding, with an INDEXED structured
     pre-filter on `ts` (only incidents within the recency window survive).
  2. $project the meta similarity score (ground_truth_label is deliberately never read).
  3. $match a similarity floor so only genuinely-similar neighbors count as evidence.
  4. $group the surviving neighbors: benign/malicious counts, mean confidence,
     mean similarity.
  5. $project the benign ratio, a composite suppress score, and the final
     decision (suppress vs escalate) via $cond.

Python does NOT loop over neighbors to decide. Its only role is: handle the
empty result (cold start / no confident neighbors) -> escalate. Never suppress
on no evidence.
"""
import copy
from memory.db import get_collection
from config.config import (VECTOR_INDEX, NUM_CANDIDATES, GATE_LIMIT,
                           RECENCY_WINDOW_SECS, MIN_EVIDENCE_SIM, MIN_MEAN_SIM,
                           SUPPRESS_RATIO, MIN_MEAN_CONF)

def build_pipeline(query_embedding, now_ts):
    since = int(now_ts) - RECENCY_WINDOW_SECS
    return [
        {"$vectorSearch": {
            "index": VECTOR_INDEX,
            "path": "embedding",
            "queryVector": query_embedding,
            "numCandidates": NUM_CANDIDATES,
            "limit": GATE_LIMIT,
            "filter": {"ts": {"$gte": since}},     # indexed recency pre-filter
        }},
        {"$project": {
            "_id": 0,
            "verdict": 1,
            "confidence": 1,
            "ts": 1,
            "score": {"$meta": "vectorSearchScore"},
            # ground_truth_label intentionally NOT projected (eval-only firewall)
        }},
        {"$match": {"score": {"$gte": MIN_EVIDENCE_SIM}}},   # similarity floor
        {"$group": {
            "_id": None,
            "n": {"$sum": 1},
            "benign": {"$sum": {"$cond": [{"$eq": ["$verdict", "benign"]}, 1, 0]}},
            "malicious": {"$sum": {"$cond": [{"$eq": ["$verdict", "malicious"]}, 1, 0]}},
            "mean_conf": {"$avg": "$confidence"},
            "mean_score": {"$avg": "$score"},
            "top_score": {"$max": "$score"},
        }},
        {"$project": {
            "_id": 0, "n": 1, "benign": 1, "malicious": 1,
            "mean_conf": {"$round": ["$mean_conf", 3]},
            "mean_score": {"$round": ["$mean_score", 3]},
            "top_score": {"$round": ["$top_score", 3]},
            "benign_ratio": {"$round": [{"$divide": ["$benign", "$n"]}, 3]},
            "suppress_score": {"$round": [
                {"$multiply": [
                    {"$divide": ["$benign", "$n"]},
                    "$mean_conf",
                    "$mean_score"]}, 3]},
            "decision": {"$cond": [
                {"$and": [
                    {"$gte": [{"$divide": ["$benign", "$n"]}, SUPPRESS_RATIO]},
                    {"$gte": ["$mean_conf", MIN_MEAN_CONF]},
                    {"$gte": ["$mean_score", MIN_MEAN_SIM]},
                ]},
                "suppress", "escalate"]},
        }},
    ]

def _printable(pipeline):
    p = copy.deepcopy(pipeline)
    qv = p[0]["$vectorSearch"]["queryVector"]
    p[0]["$vectorSearch"]["queryVector"] = f"<{len(qv)}-dim voyage embedding>"
    return p

def decide(query_embedding, now_ts, print_pipeline=True):
    import json
    pipeline = build_pipeline(query_embedding, now_ts)
    if print_pipeline:
        print("  --- Atlas aggregation pipeline (server-side decision) ---")
        print("  " + json.dumps(_printable(pipeline), indent=2).replace("\n", "\n  "))
        print("  --------------------------------------------------------")

    res = list(get_collection().aggregate(pipeline))

    if not res:
        # cold start OR no neighbor cleared the similarity floor: never suppress on no evidence
        stats = {"n": 0, "benign": 0, "malicious": 0, "mean_conf": None,
                 "mean_score": None, "benign_ratio": None, "suppress_score": None}
        return {"decision": "escalate",
                "reason": "no confident recent neighbors (cold start / below similarity floor)",
                "neighbor_stats": stats}

    stats = res[0]
    decision = stats.pop("decision")
    if decision == "suppress":
        reason = (f"{stats['benign']}/{stats['n']} recent neighbors benign "
                  f"(ratio {stats['benign_ratio']} >= {SUPPRESS_RATIO}), "
                  f"mean_conf {stats['mean_conf']} >= {MIN_MEAN_CONF}, "
                  f"mean_sim {stats['mean_score']} >= {MIN_MEAN_SIM}")
    else:
        reason = (f"neighbors not confidently benign "
                  f"(benign {stats['benign']}/{stats['n']}, malicious {stats['malicious']}, "
                  f"ratio {stats['benign_ratio']}, mean_conf {stats['mean_conf']}, "
                  f"mean_sim {stats['mean_score']})")
    return {"decision": decision, "reason": reason, "neighbor_stats": stats}
