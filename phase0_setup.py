"""
Phase 0 plumbing:
  1. connect to Atlas
  2. create harness.incidents
  3. create incident_vec vector index (dim 1024, cosine)
  4. seed one doc with a Voyage embedding
  5. run one $vectorSearch and print the hit
"""
import time, datetime
from pymongo.operations import SearchIndexModel
from pymongo.errors import OperationFailure
from config.config import DB_NAME, COLLECTION, VECTOR_INDEX, EMBED_DIM, SIMILARITY
from memory.db import get_client, get_collection
from monitor.embed import embed

def ensure_collection():
    db = get_client()[DB_NAME]
    if COLLECTION not in db.list_collection_names():
        db.create_collection(COLLECTION)
        print(f"[+] created {DB_NAME}.{COLLECTION}")
    else:
        print(f"[=] {DB_NAME}.{COLLECTION} exists")

def ensure_vector_index(col):
    existing = {i["name"] for i in col.list_search_indexes()}
    if VECTOR_INDEX in existing:
        print(f"[=] search index '{VECTOR_INDEX}' exists")
        return
    model = SearchIndexModel(
        name=VECTOR_INDEX,
        type="vectorSearch",
        definition={"fields": [{
            "type": "vector",
            "path": "embedding",
            "numDimensions": EMBED_DIM,
            "similarity": SIMILARITY,
        }]},
    )
    col.create_search_index(model=model)
    print(f"[+] created vector index '{VECTOR_INDEX}' (dim {EMBED_DIM}, {SIMILARITY})")

def wait_queryable(col, timeout=180):
    print("[.] waiting for index to become queryable ...")
    t0 = time.time()
    while time.time() - t0 < timeout:
        for i in col.list_search_indexes():
            if i["name"] == VECTOR_INDEX and i.get("queryable"):
                print(f"[+] index queryable after {int(time.time()-t0)}s")
                return True
        time.sleep(5)
    print("[!] timed out waiting for queryable index")
    return False

def seed(col):
    text = ("container target crashed with segmentation fault after malformed "
            "input; process exited 139 and docker restarted it twice")
    vec = embed(text)[0]
    doc = {
        "episode_id": "seed-0",
        "signature_text": text,
        "embedding": vec,
        "cheap_features": {"restart_count": 2, "oom_kills": 0, "nonzero_exit_count": 1,
                           "failure_rate": 1.0, "distinct_error_types": 1,
                           "cpu_spike": 0, "mem_spike": 0, "conn_refused_count": 0},
        "verdict": "malicious", "confidence": 0.9,
        "ground_truth_label": "attack",
        "timestamp": datetime.datetime.utcnow(),
    }
    col.replace_one({"episode_id": "seed-0"}, doc, upsert=True)
    print("[+] seeded episode_id=seed-0")
    return text

def vsearch(col, text):
    qv = embed(text, input_type="query")[0]
    pipe = [
        {"$vectorSearch": {
            "index": VECTOR_INDEX, "path": "embedding",
            "queryVector": qv, "numCandidates": 50, "limit": 3}},
        {"$project": {"_id": 0, "episode_id": 1, "signature_text": 1,
                      "verdict": 1, "ground_truth_label": 1,
                      "score": {"$meta": "vectorSearchScore"}}},
    ]
    return list(col.aggregate(pipe))

if __name__ == "__main__":
    ensure_collection()
    col = get_collection()
    ensure_vector_index(col)
    wait_queryable(col)
    text = seed(col)
    print("\n[.] running $vectorSearch on seeded footprint ...")
    import json
    hits = []
    for i in range(12):  # Atlas Search lags fresh writes; retry
        hits = vsearch(col, "segfault crash restart after bad input")
        if hits:
            if i:
                print(f"[.] indexed after ~{i*5}s")
            break
        time.sleep(5)
    print(json.dumps(hits, indent=2, default=str))
    assert any(h["episode_id"] == "seed-0" for h in hits), "seed not returned!"
    print("\n[OK] Phase 0 plumbing verified: seed came back from vector search.")
