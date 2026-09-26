"""Expensive tier. Input: signature_text + recent action context (rich text).
Output: {verdict, confidence, reasoning}. Every verdict cached to disk keyed by
a hash of the input. Deterministic fallback if network/key unavailable."""
import os, json, hashlib, re, requests
from config.config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL

CACHE_DIR = "llm_cache"
os.makedirs(CACHE_DIR, exist_ok=True)

SYSTEM = (
    "You are a security monitor for a containerized service. You receive an "
    "observation-only footprint of one episode: docker events with exit codes, "
    "container log tallies, client request outcomes, and resource use. Decide "
    "MALICIOUS vs BENIGN.\n"
    "Treat these as MALICIOUS attack signatures:\n"
    "- A process crash from input: a die event with a nonzero exit code such as "
    "139 (SIGSEGV) after client requests indicates an exploit or crash-inducing input.\n"
    "- An out-of-memory kill: an 'oom' event or exit code 137 means memory was "
    "exhausted by client-driven load. This is a resource-exhaustion attack, NOT "
    "benign memory pressure. Do not dismiss it as a minor issue.\n"
    "- A burst of refused or reset connections, or many connection attempts, "
    "indicates port scanning or probing. Do not read refused connections as normal.\n"
    "- Repeated authentication failures indicate credential brute force.\n"
    "Treat these as BENIGN:\n"
    "- Normal request/response traffic, health checks, or routine reads with no "
    "failures and no docker events.\n"
    "- A CLEAN restart: a die event with exit code 0 and NO crash, oom, refusal, "
    "or auth-failure signatures indicates a legitimate config reload or graceful restart.\n"
    "Key distinction: an exit-0 restart with no error signatures is benign; an "
    "exit 139, an exit 137, or an 'oom' event is malicious.\n"
    "Reply ONLY with compact JSON: {\"verdict\":\"malicious\"|\"benign\","
    "\"confidence\":0..1,\"reasoning\":\"one sentence\"}.")

def _key(signature_text, context):
    h = hashlib.sha256()
    h.update(LLM_MODEL.encode()); h.update(b"\x00")
    h.update(SYSTEM.encode()); h.update(b"\x00")   # prompt version -> stale verdicts miss
    h.update(signature_text.encode()); h.update(b"\x00")
    h.update((context or "").encode())
    return h.hexdigest()

def _cache_get(k):
    p = os.path.join(CACHE_DIR, k + ".json")
    if os.path.exists(p):
        try: return json.load(open(p))
        except Exception: return None
    return None

def _cache_put(k, v):
    json.dump(v, open(os.path.join(CACHE_DIR, k + ".json"), "w"))

def _fallback(signature_text):
    """Deterministic stand-in (reads the rich text, like the LLM tier). Used when
    the network/key is unavailable so a dropped connection cannot kill a run."""
    t = signature_text.lower()
    mal = [r"exit=139", r"exit=137", r"\boom\b", r"segfault", r"auth failure x[1-9]",
           r"connection-refused\.\s", r"[1-9]\d+ connection-refused",
           r"error signatures observed"]
    hits = [p for p in mal if re.search(p, t)]
    if hits:
        return {"verdict": "malicious", "confidence": 0.8,
                "reasoning": f"deterministic fallback matched attack signatures: {hits[:3]}",
                "source": "fallback"}
    return {"verdict": "benign", "confidence": 0.75,
            "reasoning": "deterministic fallback saw no crash/error/scan signatures",
            "source": "fallback"}

def verdict(signature_text, context="", allow_network=True, no_cache=False, no_write=False):
    """no_cache=True skips the cache READ (forces a real call when allow_network).
    no_write=True skips the cache WRITE (leaves no persistent trace — a live run
    stays fresh and repeatable, and the committed offline cache is untouched)."""
    k = _key(signature_text, context)
    if not no_cache:
        cached = _cache_get(k)
        if cached is not None:
            cached["cached"] = True
            return cached

    result = None
    if allow_network and LLM_API_KEY:
        try:
            r = requests.post(
                f"{LLM_BASE_URL}/chat/completions",
                headers={"Authorization": f"Bearer {LLM_API_KEY}",
                         "Content-Type": "application/json"},
                json={"model": LLM_MODEL, "temperature": 0,
                      "messages": [{"role": "system", "content": SYSTEM},
                                   {"role": "user",
                                    "content": f"RECENT CONTEXT:\n{context}\n\nFOOTPRINT:\n{signature_text}"}]},
                timeout=30)
            r.raise_for_status()
            content = r.json()["choices"][0]["message"]["content"]
            m = re.search(r"\{.*\}", content, re.S)
            parsed = json.loads(m.group(0) if m else content)
            result = {"verdict": str(parsed["verdict"]).lower(),
                      "confidence": float(parsed.get("confidence", 0.7)),
                      "reasoning": parsed.get("reasoning", ""),
                      "source": "llm"}
        except Exception as e:
            result = _fallback(signature_text)
            result["reasoning"] += f" [network error: {type(e).__name__}]"

    if result is None:
        result = _fallback(signature_text)

    if not no_write:
        _cache_put(k, result)
    result["cached"] = False
    return result
