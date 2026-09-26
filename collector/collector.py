"""Collector: the ONLY component that touches Docker.
Observes docker events, container logs, docker stats, exit codes during an
episode window and assembles a footprint object. No authored footprints:
every feature is derived from real Docker/client observation.

Footprint contract:
  cheap_features: {restart_count, oom_kills, nonzero_exit_count, failure_rate,
                   distinct_error_types, cpu_spike, mem_spike, conn_refused_count}
  signature_text: NL rendering of the real event/log/outcome stream (LLM reads this)
  episode_id, ground_truth_label, timestamp
"""
import subprocess, threading, time, json, re, datetime, sys, os

CONTAINER = "harness-target"
CPU_SPIKE_PCT = 50.0   # peak cpu% above this -> spike
MEM_SPIKE_MIB = 40.0   # peak mem above this -> spike (limit is 100 MiB)
SETTLE_S = 6.0         # let restart/events land after client finishes

# ---------- docker helpers (subprocess CLI) ----------
def _dk(args, timeout=15):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)

def restart_count():
    r = _dk(["inspect", "-f", "{{.RestartCount}}", CONTAINER])
    try: return int(r.stdout.strip())
    except ValueError: return 0

def status():
    r = _dk(["inspect", "-f", "{{.State.Status}}", CONTAINER])
    return r.stdout.strip()

def wait_running(timeout=90):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if status() == "running":
            time.sleep(0.5)
            return True
        time.sleep(1)
    return False

def events_since(t0):
    r = _dk(["events", "--since", str(int(t0)), "--until", str(int(time.time())),
             "--filter", f"container={CONTAINER}", "--format", "{{json .}}"], timeout=20)
    out = []
    for line in r.stdout.strip().splitlines():
        try: out.append(json.loads(line))
        except json.JSONDecodeError: pass
    return out

def logs_since(t0):
    r = _dk(["logs", "--since", str(int(t0)), CONTAINER], timeout=20)
    return (r.stdout or "") + (r.stderr or "")

# ---------- stats sampler ----------
_MEM_UNIT = {"B":1/1048576,"KIB":1/1024,"MIB":1.0,"GIB":1024.0}
def _parse_mem(s):
    m = re.match(r"([\d.]+)\s*([A-Za-z]+)", s.strip())
    if not m: return 0.0
    return float(m.group(1)) * _MEM_UNIT.get(m.group(2).upper(), 1.0)

class StatsSampler(threading.Thread):
    def __init__(self, interval=1.0):
        super().__init__(daemon=True)
        self.interval = interval; self._stopev = threading.Event()
        self.peak_cpu = 0.0; self.peak_mem = 0.0; self.samples = 0
    def run(self):
        while not self._stopev.is_set():
            r = _dk(["stats", "--no-stream", "--format", "{{.CPUPerc}}|{{.MemUsage}}", CONTAINER], timeout=10)
            line = r.stdout.strip()
            if "|" in line:
                cpu_s, mem_s = line.split("|", 1)
                try: self.peak_cpu = max(self.peak_cpu, float(cpu_s.strip().rstrip("%")))
                except ValueError: pass
                self.peak_mem = max(self.peak_mem, _parse_mem(mem_s.split("/")[0]))
                self.samples += 1
            self._stopev.wait(self.interval)
    def stop(self): self._stopev.set()

# ---------- feature + signature assembly ----------
def _classify_events(events):
    dies = []      # exit codes of die events
    ooms = 0
    starts = 0
    for e in events:
        act = e.get("Action", "")
        if act == "oom": ooms += 1
        elif act == "die":
            code = e.get("Actor", {}).get("Attributes", {}).get("exitCode", "")
            dies.append(code)
        elif act in ("start", "restart"): starts += 1
    return dies, ooms, starts

def build_footprint(episode_id, family, label, client_out, rc_before, rc_after,
                    events, logs, sampler):
    dies, ooms, starts = _classify_events(events)
    nonzero = [c for c in dies if c not in ("0", "", "<no value>", None)]
    restart_delta = max(rc_after - rc_before, 0)

    # distinct error types from REAL signal
    etypes = set()
    if "139" in dies: etypes.add("segfault")
    if ooms or "137" in dies: etypes.add("oom")
    if "134" in dies: etypes.add("abort")
    if re.search(r"auth failure", logs): etypes.add("auth_failure")
    if client_out.get("conn_refused", 0) > 0: etypes.add("conn_refused")

    requests = client_out.get("requests", 0) or 0
    failures = client_out.get("failures", 0) or 0
    refused  = client_out.get("conn_refused", 0) or 0
    failure_rate = round(failures / requests, 3) if requests else 0.0

    cheap = {
        "restart_count": restart_delta,
        "oom_kills": ooms,
        "nonzero_exit_count": len(nonzero),
        "failure_rate": failure_rate,
        "distinct_error_types": len(etypes),
        "cpu_spike": 1 if sampler.peak_cpu > CPU_SPIKE_PCT else 0,
        "mem_spike": 1 if sampler.peak_mem > MEM_SPIKE_MIB else 0,
        "conn_refused_count": refused,
    }

    # signature_text: ordered NL rendering of the real stream
    accepts = len(re.findall(r"connection accepted", logs))
    authfails = len(re.findall(r"auth failure", logs))
    ev_seq = []
    for e in events:
        act = e.get("Action", "")
        if act == "die":
            ev_seq.append(f"die(exit={e.get('Actor',{}).get('Attributes',{}).get('exitCode','?')})")
        elif act in ("oom", "start", "restart", "kill"):
            ev_seq.append(act)
    parts = [
        f"Episode {episode_id} family={family}.",
        f"Client opened {requests} operations to target:9000; "
        f"{failures} failed, {refused} connection-refused. "
        f"Note: {client_out.get('note','')}.",
    ]
    if ev_seq:
        parts.append("Docker events (time order): " + ", ".join(ev_seq) + ".")
    else:
        parts.append("Docker events: none (container stable).")
    parts.append(f"Container logs: 'connection accepted' x{accepts}, 'auth failure' x{authfails}.")
    if etypes:
        parts.append("Error signatures observed: " + ", ".join(sorted(etypes)) + ".")
    parts.append(f"Peak cpu {sampler.peak_cpu:.1f}%, peak mem {sampler.peak_mem:.1f} MiB "
                 f"over {sampler.samples} samples.")
    signature_text = " ".join(parts)

    return {
        "episode_id": episode_id,
        "ground_truth_label": label,
        "cheap_features": cheap,
        "signature_text": signature_text,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "_client": client_out,   # kept for debugging, not part of the monitor contract
    }

# ---------- orchestrate one episode ----------
def capture_episode(episode_id, kind, family, seed):
    """kind: 'attack' or 'benign'. Runs the client, observes Docker, returns footprint."""
    if not wait_running():
        print(f"[!] {CONTAINER} not running before {episode_id}", file=sys.stderr)
    rc_before = restart_count()
    t0 = time.time() - 1  # small backdate so we don't miss the first event

    sampler = StatsSampler(interval=1.0); sampler.start()

    script = "attacker/attack.py" if kind == "attack" else "benign/benign.py"
    proc = subprocess.run([sys.executable, script, family, str(seed)],
                          capture_output=True, text=True, timeout=180)
    client_out = {}
    for line in proc.stdout.strip().splitlines():
        try: client_out = json.loads(line)
        except json.JSONDecodeError: pass
    if not client_out:
        client_out = {"family": family, "label": kind, "requests": 0,
                      "failures": 0, "conn_refused": 0, "note": "client produced no output",
                      "stderr": proc.stderr[-200:]}

    time.sleep(SETTLE_S)
    sampler.stop(); sampler.join(timeout=5)

    events = events_since(t0)
    logs = logs_since(t0)
    return build_footprint(episode_id, family, kind, client_out,
                           rc_before, restart_count(), events, logs, sampler)
