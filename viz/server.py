"""Single-page glass-box demo server (stdlib only).
  GET /            -> the page
  GET /events?mode=live|offline -> Server-Sent Events, one per episode + a 'done'.
Live drives the real Atlas/Voyage/LLM pipeline; offline uses caches + local mirror.
"""
import os, sys, json, traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(ROOT))  # project root importable

from viz.trace import live_records, offline_records

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _page(self):
        html = open(os.path.join(ROOT, "index.html"), "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers(); self.wfile.write(html)

    def _sse(self, mode):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        def send(ev, obj):
            self.wfile.write(f"event: {ev}\ndata: {json.dumps(obj)}\n\n".encode())
            self.wfile.flush()
        try:
            gen = live_records() if mode == "live" else offline_records()
            send("start", {"mode": mode})
            last = None
            for rec in gen:
                send("episode", rec); last = rec
            send("done", {"mode": mode,
                          "expensive": last["cum_cost"] if last else 0,
                          "saved": last["saved"] if last else 0,
                          "recall": last["recall"] if last else 1.0})
        except BrokenPipeError:
            pass
        except Exception as e:
            traceback.print_exc()
            try: send("error", {"mode": mode, "error": f"{type(e).__name__}: {e}"})
            except Exception: pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._page()
        elif u.path == "/events":
            mode = (parse_qs(u.query).get("mode", ["offline"])[0]).lower()
            self._sse("live" if mode == "live" else "offline")
        else:
            self.send_response(404); self.end_headers()

def main():
    port = int(os.environ.get("DEMO_PORT", "8077"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    print(f"[.] glass-box demo at  http://127.0.0.1:{port}")
    print("    open it, then click Run LIVE (real Atlas) or Run OFFLINE (cached).")
    try: srv.serve_forever()
    except KeyboardInterrupt: print("\n[.] stopped")

if __name__ == "__main__":
    main()
