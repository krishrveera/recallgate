# On-Demand Monitor for Cyber-Capable Agents

A monitoring harness that learns an environment's "normal" system behavior, stores it as
incident memory in MongoDB Atlas, and escalates to expensive LLM analysis **only on
unfamiliar footprints**. It gets cheaper over a session as memory fills, while never
suppressing a real attack.

Signal is real, not authored: a deliberately vulnerable container is driven by real attack
and benign scripts, and a collector reads only Docker-level observation (events, logs,
stats, exit codes) — no syscall/eBPF/ptrace instrumentation.

## The idea in one line
Escalate to the costly LLM only on unfamiliar system footprints, remember verdicts in
MongoDB, and drive the expensive-call rate down without losing recall on real attacks.

## Two-tier design + the decision engine
- **Cheap tier** (`monitor/cheap.py`): reads ONLY numeric aggregates (restarts, OOM kills,
  nonzero exits, refused connections, error types). All-quiet episodes are ignored for free.
- **Gate** (`monitor/gate.py`): on anomaly, ONE Atlas aggregation makes the decision
  server-side — `$vectorSearch` (with an indexed `ts` recency filter) → `$project` (score;
  ground-truth never read) → `$match` (evidence floor) → `$group` → `$project` (benign_ratio,
  mean_conf, mean_sim, decision). Suppress iff enough recent neighbours are confidently benign.
- **Hard-signal override**: any footprint with a real crash/OOM/refused-burst/error signal is
  never suppressed — attack recall is guaranteed regardless of LLM or memory error.
- **Expensive tier** (`monitor/llm.py`): reads the rich `signature_text`; verdict cached to disk.
- **Memory** (`memory/`): every escalation upserts the incident with its embedding + verdict.

## Setup
```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env         # fill MONGODB_URI, VOYAGE_API_KEY, LLM_API_KEY
python reindex.py            # create incident_vec (dim 1024, cosine, filter ts)
```

## Run — three modes, know which one you're in
| mode | embeddings | LLM | Atlas | network |
|------|-----------|-----|-------|---------|
| **offline** | cache only | cache only | local mirror | none (keys can be blank) |
| **live** | cache, live on miss | **real call every escalation** | real cluster | yes |
| **fresh** | **live (cache bypassed)** | **real call every escalation** | real cluster | yes |

offline is the venue-safe fallback; live proves the LLM is really queried; fresh forces everything live.

```bash
# offline deterministic replay (runs with the network + keys disabled)
python demo.py                       # recall 1.00, cost series, writes data/cost_curve.png

# live: real Atlas + a real LLM call on every escalation
python demo.py --live                # warms memory, then runs held-out with live LLM calls
python demo.py --fresh               # like --live, also bypasses the embedding cache
python demo.py --live --shuffle 42   # same stream, different order (cost savings are order-free)
python demo.py --live --footprint FILE.json   # judge-supplied footprint, real live call

# glass-box single-page UI
python viz/server.py                 # http://127.0.0.1:8077 -> Offline · all cache / Live · real LLM / Fresh · no cache
```

Held-out set (`data/heldout.jsonl`, unseen seeds, not pre-cached) produces genuine live LLM
calls in live/fresh mode; attacks among them are still escalated (recall holds on unseen inputs).

## Rebuild from scratch (optional)
```bash
python phase0_setup.py       # Atlas plumbing + seed + one $vectorSearch
cd target && docker compose up -d --build && cd ..   # vulnerable target
python phase1_capture.py     # capture real footprints -> data/footprints.jsonl
python phase3_loop.py        # full stream: recall hard-gate + cost trend
python -m eval.gap           # same-family vs cross-family separation gap
python -m eval.adfa          # ADFA-LD replay fallback (real labeled syscall traces)
```

## Results
- Attack recall **1.00** on the stream, on a shuffled order, and on unseen held-out footprints.
- Expensive-calls-per-episode bends from ~0.67 toward ~0.33 as memory fills.
- Offline replay reproduces the online decisions exactly with all keys blanked.
