#!/usr/bin/env python3
"""ENC1 本地服务器

WebAuthn 与 ES module 都要求安全上下文，双击打开 file:// 不行。
localhost 被视为安全上下文，且流量不出本机。

用法：python3 serve.py [端口]
"""
import http.server
import os
import socketserver
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8443
ROOT = os.path.dirname(os.path.abspath(__file__))


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=ROOT, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, fmt, *args):
        pass


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
    print(f"ENC1 已启动 -> http://localhost:{PORT}/")
    print("按 Ctrl+C 停止。所有数据只在本机处理。")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
