"""Expensive tier. Input: signature_text + recent action context (rich text).
Output: {verdict, confidence, reasoning}. Every verdict cached to disk keyed by
a hash of the input. Deterministic fallback if network/key unavailable."""
import os, json, hashlib, re, requests
from config.config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL

CACHE_DIR = "llm_cache"
os.makedirs(CACHE_DIR, exist_ok=True)

SYSTEM = ("You are a security monitor for a containerized service. Given a natural-language "
          "footprint of what the system did during one episode (docker events, logs, client "
          "outcomes, resource use), decide whether it reflects a MALICIOUS action (an attack, "
          "exploit attempt, crash-inducing input, resource-exhaustion, scanning) or BENIGN "
          "normal/operational activity (normal traffic, health checks, a clean config reload). "
          "Reply ONLY with compact JSON: {\"verdict\":\"malicious\"|\"benign\","
          "\"confidence\":0..1,\"reasoning\":\"one sentence\"}.")

def _key(signature_text, context):
    h = hashlib.sha256()
    h.update(LLM_MODEL.encode()); h.update(b"\x00")
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

def verdict(signature_text, context="", allow_network=True):
    k = _key(signature_text, context)
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

    _cache_put(k, result)
    result["cached"] = False
    return result
