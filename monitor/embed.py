"""Voyage embeddings. signature_text -> 1024-dim vector.
Every embedding is cached to disk keyed by sha256(model+input_type+text), so a
recorded run can be replayed offline with no network (see demo.py)."""
import time, os, json, hashlib
import voyageai
from voyageai.error import RateLimitError
from config.config import VOYAGE_API_KEY, VOYAGE_MODEL, EMBED_DIM

CACHE_DIR = "embed_cache"
os.makedirs(CACHE_DIR, exist_ok=True)

def _ck(text, input_type):
    h = hashlib.sha256()
    h.update(VOYAGE_MODEL.encode()); h.update(b"\x00")
    h.update(input_type.encode()); h.update(b"\x00")
    h.update(text.encode())
    return os.path.join(CACHE_DIR, h.hexdigest() + ".json")

def _cache_get(text, input_type):
    p = _ck(text, input_type)
    if os.path.exists(p):
        try: return json.load(open(p))
        except Exception: return None
    return None

def _cache_put(text, input_type, vec):
    try: json.dump(vec, open(_ck(text, input_type), "w"))
    except Exception: pass

_vc = None

def _client():
    global _vc
    if _vc is None:
        if not VOYAGE_API_KEY:
            raise RuntimeError("VOYAGE_API_KEY empty. Fill .env.")
        _vc = voyageai.Client(api_key=VOYAGE_API_KEY)
    return _vc

def embed(texts, input_type="document", max_retries=6, offline=False, no_cache=False):
    """texts: str or list[str] -> list[list[float]]. Uses the disk cache first;
    only cache-missing texts hit Voyage (which also respects the free-tier 3 RPM).
    offline=True forbids any network call: a cache miss raises.
    no_cache=True skips the cache READ (forces a live embedding) but still writes."""
    if isinstance(texts, str):
        texts = [texts]
    out = [None] * len(texts)
    misses = []
    for i, t in enumerate(texts):
        c = None if no_cache else _cache_get(t, input_type)
        if c is not None:
            out[i] = c
        else:
            misses.append(i)

    if misses:
        if offline:
            raise RuntimeError(f"offline embed: {len(misses)} texts not in cache "
                               f"(record a run online first to warm embed_cache/)")
        want = [texts[i] for i in misses]
        delay = 20  # free tier is 3 RPM; wait out the window
        for attempt in range(max_retries):
            try:
                r = _client().embed(want, model=VOYAGE_MODEL, input_type=input_type)
                break
            except RateLimitError:
                if attempt == max_retries - 1:
                    raise
                print(f"[.] voyage rate-limited, waiting {delay}s ...")
                time.sleep(delay)
        for idx, vec in zip(misses, r.embeddings):
            out[idx] = vec
            _cache_put(texts[idx], input_type, vec)

    for v in out:
        assert len(v) == EMBED_DIM, f"expected {EMBED_DIM} dims, got {len(v)}"
    return out
