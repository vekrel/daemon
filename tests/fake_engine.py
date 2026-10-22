# Fake engine for supervisor tests. Listens on $VEKREL_PORT and answers 200 to every GET.
# Flags (argv, any order): delay=SECS before listening, noready (answer 404), ignore-term,
# term-file=PATH (write "graceful" there on SIGTERM, exit 0). Other args are inert markers.
import os, signal, sys, time
from http.server import BaseHTTPRequestHandler, HTTPServer

flags = dict(a.partition("=")[::2] for a in sys.argv[1:])
if "ignore-term" in flags:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
elif "term-file" in flags:
    def on_term(*_):
        open(flags["term-file"], "w").write("graceful\n")
        os._exit(0)
    signal.signal(signal.SIGTERM, on_term)
time.sleep(float(flags.get("delay", 0)))


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(404 if "noready" in flags else 200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", int(os.environ["VEKREL_PORT"])), H).serve_forever()
