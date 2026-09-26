"""Frozen config for the monitoring harness. Values here are non-secret."""
import os
from dotenv import load_dotenv

load_dotenv()

# --- secrets (from .env) ---
MONGODB_URI   = os.environ.get("MONGODB_URI", "")
VOYAGE_API_KEY = os.environ.get("VOYAGE_API_KEY", "")
LLM_API_KEY   = os.environ.get("LLM_API_KEY", "")

# --- Atlas ---
DB_NAME       = "harness"
COLLECTION    = "incidents"
VECTOR_INDEX  = "incident_vec"
EMBED_DIM     = 1024
SIMILARITY    = "cosine"

# --- Voyage ---
VOYAGE_MODEL  = "voyage-3"   # 1024 dims

# --- LLM monitor ---
LLM_BASE_URL  = "https://openrouter.ai/api/v1"
LLM_MODEL     = "openai/gpt-4o-mini"

# --- gate / retrieval ---
TOP_K         = 5
SUPPRESS_RATIO = 0.6   # >= this fraction of neighbors benign -> suppress
MIN_MEAN_CONF  = 0.6   # and mean confidence over neighbors must clear this

# --- cheap tier heuristic ---
ANOMALY_THRESHOLD = 1.0

# --- gate aggregation (Phase 2) ---
NUM_CANDIDATES      = 100    # $vectorSearch numCandidates
GATE_LIMIT          = 10     # $vectorSearch limit (top-k neighbors)
RECENCY_WINDOW_SECS = 1800   # filter: only incidents within this window (server-side)
MIN_EVIDENCE_SIM    = 0.97   # Atlas score space =(1+cos)/2; isolates same-family (~0.997) from cross-family (<=0.937)
MIN_MEAN_SIM        = 0.97   # Atlas score space; mean evidence similarity to suppress
# SUPPRESS_RATIO and MIN_MEAN_CONF defined above (0.6 / 0.6)
