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
