"""Voyage embeddings. signature_text -> 1024-dim vector."""
import time
import voyageai
from voyageai.error import RateLimitError
from config.config import VOYAGE_API_KEY, VOYAGE_MODEL, EMBED_DIM

_vc = None

def _client():
    global _vc
    if _vc is None:
        if not VOYAGE_API_KEY:
            raise RuntimeError("VOYAGE_API_KEY empty. Fill .env.")
        _vc = voyageai.Client(api_key=VOYAGE_API_KEY)
    return _vc

def embed(texts, input_type="document", max_retries=6):
    """texts: str or list[str] -> list[list[float]]. Backs off on free-tier 3 RPM limit."""
    if isinstance(texts, str):
        texts = [texts]
    delay = 20  # free tier is 3 RPM; wait out the window
    for attempt in range(max_retries):
        try:
            r = _client().embed(texts, model=VOYAGE_MODEL, input_type=input_type)
            break
        except RateLimitError:
            if attempt == max_retries - 1:
                raise
            print(f"[.] voyage rate-limited, waiting {delay}s ...")
            time.sleep(delay)
    out = r.embeddings
    for v in out:
        assert len(v) == EMBED_DIM, f"expected {EMBED_DIM} dims, got {len(v)}"
    return out
