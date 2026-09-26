"""Cheap tier. Reads ONLY cheap_features (numeric aggregates).
NEVER touches signature_text. Maps to an anomaly score via fixed heuristics.
Below threshold -> ignore the episode (no gate, no LLM, zero cost)."""
from config.config import ANOMALY_THRESHOLD

# only these keys may be read here
_ALLOWED = {"restart_count","oom_kills","nonzero_exit_count","failure_rate",
            "distinct_error_types","cpu_spike","mem_spike","conn_refused_count"}

def anomaly_score(cheap_features):
    cf = {k: cheap_features.get(k, 0) for k in _ALLOWED}   # hard firewall: numeric only
    s = 0.0
    s += 2.0 * cf["restart_count"]
    s += 3.0 * cf["oom_kills"]
    s += 2.0 * cf["nonzero_exit_count"]
    s += 1.5 * cf["failure_rate"]
    s += 1.0 * cf["distinct_error_types"]
    s += 1.0 * cf["cpu_spike"]
    s += 1.0 * cf["mem_spike"]
    s += 0.05 * min(cf["conn_refused_count"], 20)
    return round(s, 3)

def is_anomaly(cheap_features):
    return anomaly_score(cheap_features) >= ANOMALY_THRESHOLD


# Hard-failure signals: a footprint showing any of these is a real crash / scan /
# error burst and must NEVER be suppressed by memory, regardless of stored verdicts.
# (config_reload -- a clean restart -- has all of these at zero, so it stays suppressible.)
def has_hard_signal(cheap_features):
    cf = {k: cheap_features.get(k, 0) for k in _ALLOWED}
    return (cf["oom_kills"] > 0 or cf["nonzero_exit_count"] > 0
            or cf["conn_refused_count"] > 0 or cf["distinct_error_types"] > 0)
