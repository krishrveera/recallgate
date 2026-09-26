"""Real benign families. Surface variation (counts, payloads, order) but a
shared footprint shape: all succeed, no crash, low resource. Emits one json line."""
import sys, json, socket, time, random

HOST, PORT = "127.0.0.1", 9000

def _req(payload, timeout=2.0):
    try:
        s = socket.create_connection((HOST, PORT), timeout=timeout)
    except ConnectionRefusedError:
        return "refused"
    except OSError:
        return "fail"
    try:
        s.sendall(payload); s.settimeout(timeout)
        r = s.recv(4096); s.close()
        return "ok" if r else "fail"
    except OSError:
        return "fail"

def run(family, seed):
    rnd = random.Random(seed)
    req = fail = refused = 0

    def do(payload):
        nonlocal req, fail, refused
        st = _req(payload); req += 1
        if st == "refused": refused += 1
        elif st != "ok": fail += 1

    if family == "normal_requests":
        words = ["hello","status","ready","ok","ping","data","user","node"]
        for _ in range(rnd.randint(8, 15)):
            k = rnd.random()
            if k < 0.3: do(b"PING\n")
            elif k < 0.6: do(b"ECHO " + rnd.choice(words).encode() + b"\n")
            elif k < 0.8: do(b"AUTH bob s3cret\n")
            else: do(b"GET /var/data/%d\n" % rnd.randint(1,99))
            time.sleep(rnd.uniform(0.02, 0.08))
        note = "mixed normal traffic"

    elif family == "health_checks":
        for _ in range(rnd.randint(10, 20)):
            do(b"PING\n"); time.sleep(rnd.uniform(0.02, 0.06))
        note = "periodic health pings"

    elif family == "config_reload":
        # legitimate operator action: some traffic, then a clean reload (restart).
        # Restart-shaped footprint but exit 0 -> benign; memory must learn this.
        reasons = ["rotate-tls","update-flags","apply-limits","refresh-acl","new-build"]
        for _ in range(rnd.randint(2, 4)):
            do(b"PING\n"); time.sleep(rnd.uniform(0.02, 0.05))
        do(b"ECHO reload:" + rnd.choice(reasons).encode() + b"\n")
        # trigger clean restart
        try:
            s = socket.create_connection((HOST, PORT), timeout=2); req += 1
            s.sendall(b"RELOAD\n")
            try: s.settimeout(1); s.recv(64)
            except Exception: pass
            s.close()
        except OSError:
            fail += 1
        time.sleep(3.5)                 # wait out the restart window (avoid noise)
        for _ in range(rnd.randint(2, 4)):
            do(b"PING\n"); time.sleep(rnd.uniform(0.02, 0.05))
        note = "config reload with clean restart"

    elif family == "file_ops":
        dirs = ["/var/data","/srv/files","/tmp/cache","/opt/app/logs"]
        for _ in range(rnd.randint(8, 16)):
            do(b"GET %s/%d\n" % (rnd.choice(dirs).encode(), rnd.randint(1,999)))
            time.sleep(rnd.uniform(0.02, 0.07))
        note = "routine file reads"

    else:
        print(json.dumps({"error": f"unknown family {family}"})); sys.exit(1)

    print(json.dumps({"family": family, "label": "benign", "seed": seed,
                      "requests": req, "failures": fail,
                      "conn_refused": refused, "note": note}))

if __name__ == "__main__":
    run(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 0)
