"""Real attack families against the target's published port. Target-only.
Emits ONE json line of genuine client-side outcomes (no authored footprint)."""
import sys, json, socket, time, random

HOST, PORT = "127.0.0.1", 9000

def _conn(timeout=2.0):
    return socket.create_connection((HOST, PORT), timeout=timeout)

def _one(payload, read=True, timeout=2.0):
    """One request. Returns ('ok'|'fail'|'refused', reply_bytes)."""
    try:
        s = _conn(timeout)
    except ConnectionRefusedError:
        return "refused", b""
    except OSError:
        return "fail", b""
    try:
        s.sendall(payload)
        if read:
            s.settimeout(timeout)
            try: r = s.recv(4096)
            except Exception: r = b""
        else:
            r = b""
        s.close()
        return ("ok" if r else "fail"), r
    except (BrokenPipeError, ConnectionResetError, OSError):
        return "fail", b""

def run(family, seed):
    rnd = random.Random(seed)
    req = fail = refused = 0
    note = ""

    if family == "malformed_segfault":
        # oversized AUTH token overflows a fixed stack buffer -> SIGSEGV
        overflow = b"AUTH " + b"A" * rnd.randint(400, 800) + b" x\n"
        st, _ = _one(overflow); req += 1
        if st == "refused": refused += 1
        if st != "ok": fail += 1
        # probe again while it restarts -> real connection-refused signal
        for _ in range(rnd.randint(3, 6)):
            time.sleep(0.4)
            st, _ = _one(b"PING\n"); req += 1
            if st == "refused": refused += 1
            if st != "ok": fail += 1
        note = "oversized AUTH payload -> segfault"

    elif family == "resource_exhaustion":
        # ALLOC flood on one connection -> container mem limit -> OOM kill
        chunk = rnd.choice([6_000_000, 8_000_000, 10_000_000])
        try:
            s = _conn(3.0); req += 1
            for _ in range(rnd.randint(30, 45)):
                s.sendall(b"ALLOC %d\n" % chunk); time.sleep(0.03)
            s.close()
        except (ConnectionRefusedError,) : refused += 1; fail += 1
        except OSError: fail += 1
        for _ in range(rnd.randint(2, 5)):
            time.sleep(0.5)
            st, _ = _one(b"PING\n"); req += 1
            if st == "refused": refused += 1
            if st != "ok": fail += 1
        note = f"ALLOC flood {chunk}B -> OOM"

    elif family == "auth_bruteforce":
        n = rnd.randint(20, 35)
        users = ["admin","root","bob","svc","test","oracle"]
        for _ in range(n):
            u = rnd.choice(users); p = rnd.randint(1000,9999)
            st, r = _one(b"AUTH %s pw%d\n" % (u.encode(), p)); req += 1
            if st == "refused": refused += 1
            if st != "ok": fail += 1   # AUTH FAIL still replies -> ok; count app-fail below
        note = f"{n} failed-auth attempts"

    elif family == "port_scan":
        # sweep the target's published port range; only 9000 serves, the rest
        # are bound-but-closed inside the container and RST (empty reply).
        rounds = rnd.randint(3, 6)
        for _ in range(rounds):
            for p in range(9000, 9011):
                req += 1
                try:
                    s = socket.create_connection((HOST, p), timeout=1.0)
                    s.sendall(b"PING\n"); s.settimeout(0.5)
                    try: r = s.recv(64)
                    except Exception: r = b""
                    s.close()
                    if not r:                 # container reset a closed port
                        refused += 1; fail += 1
                except ConnectionRefusedError:
                    refused += 1; fail += 1
                except OSError:
                    fail += 1
                time.sleep(0.01)
        note = f"scanned ports 9000-9010 x{rounds} rounds"

    else:
        print(json.dumps({"error": f"unknown family {family}"})); sys.exit(1)

    print(json.dumps({"family": family, "label": "attack", "seed": seed,
                      "requests": req, "failures": fail,
                      "conn_refused": refused, "note": note}))

if __name__ == "__main__":
    run(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 0)
