"""Rebuild incident_vec with a filterable numeric ts field, wait until Active."""
import time
from pymongo.operations import SearchIndexModel
from config.config import VECTOR_INDEX, EMBED_DIM, SIMILARITY
from memory.db import get_collection

DEFINITION = {"fields": [
    {"type": "vector", "path": "embedding", "numDimensions": EMBED_DIM, "similarity": SIMILARITY},
    {"type": "filter", "path": "ts"},     # numeric epoch seconds -> $vectorSearch filter
]}

def main():
    col = get_collection()
    existing = {i["name"] for i in col.list_search_indexes()}
    if VECTOR_INDEX in existing:
        print(f"[.] dropping existing '{VECTOR_INDEX}' ...")
        col.drop_search_index(VECTOR_INDEX)
        for _ in range(60):
            if VECTOR_INDEX not in {i["name"] for i in col.list_search_indexes()}:
                break
            time.sleep(2)
        print("[+] dropped")
    col.create_search_index(model=SearchIndexModel(
        name=VECTOR_INDEX, type="vectorSearch", definition=DEFINITION))
    print(f"[+] created '{VECTOR_INDEX}' with vector + filter(ts)")
    t0 = time.time()
    while time.time() - t0 < 240:
        for i in col.list_search_indexes():
            if i["name"] == VECTOR_INDEX:
                st = i.get("status"); q = i.get("queryable")
                if q and st == "READY":
                    print(f"[+] index ACTIVE/READY after {int(time.time()-t0)}s")
                    return
        time.sleep(5)
    print("[!] timed out waiting for READY")

if __name__ == "__main__":
    main()
