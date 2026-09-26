"""Incident memory. Every escalation upserts an incident here.
Stores ground_truth_label (for the eval harness only) — the GATE never reads it."""
import datetime
from memory.db import get_collection

def write_incident(episode_id, signature_text, embedding, verdict, confidence,
                   ground_truth_label, cheap_features, ts):
    doc = {
        "episode_id": episode_id,
        "signature_text": signature_text,
        "embedding": embedding,
        "verdict": verdict,                 # the system's own past LLM judgment (memory)
        "confidence": confidence,
        "ground_truth_label": ground_truth_label,  # eval only; gate must never read
        "cheap_features": cheap_features,
        "ts": int(ts),                      # epoch seconds; indexed filter field
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }
    get_collection().replace_one({"episode_id": episode_id}, doc, upsert=True)
    return doc

def wipe():
    get_collection().delete_many({})

def count():
    return get_collection().count_documents({})
