#!/usr/bin/env python3
"""e2e test proxy between the phone and the kidctl server.

The phone reaches the host at 10.0.2.2, which keeps working when
no_debugging_features switches adb (and adb reverse) off. Everything is passed
through unchanged, except: while the file CORRUPT_FLAG exists, agent APK
downloads (/api/v1/agent/...) get one byte flipped, so the e2e can prove the
agent refuses an APK whose SHA-256 does not match the offer.

Usage: proxy.py <listen-port> <server-port> <corrupt-flag-file>
"""
import http.client
import http.server
import os
import sys

LISTEN, UPSTREAM, FLAG = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
HOP = {"connection", "keep-alive", "transfer-encoding", "proxy-connection", "upgrade", "te", "trailer"}


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # one request per connection: simple and enough here

    def relay(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else None
        up = http.client.HTTPConnection("127.0.0.1", UPSTREAM, timeout=60)
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        up.request(self.command, self.path, body=body, headers=headers)
        r = up.getresponse()
        data = r.read()
        if self.path.startswith("/api/v1/agent/") and r.status == 200 and os.path.exists(FLAG) and data:
            data = data[:-1] + bytes([data[-1] ^ 0xFF])
            print(f"proxy: corrupted {self.path} ({len(data)} bytes)", flush=True)
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() not in HOP and k.lower() != "content-length":
                self.send_header(k, v)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        up.close()

    do_GET = do_POST = relay

    def log_message(self, fmt, *args):
        print("proxy: " + fmt % args, flush=True)


http.server.ThreadingHTTPServer(("127.0.0.1", LISTEN), Proxy).serve_forever()
