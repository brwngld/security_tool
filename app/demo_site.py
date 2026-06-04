from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def demo_page(path: str) -> tuple[int, dict[str, str], str]:
    if path == "/":
        return (
            200,
            {
                "Content-Type": "text/html; charset=utf-8",
                "Server": "nginx/1.24.0",
                "CF-Ray": "demo-ray",
                "Set-Cookie": "sessionid=demo123; Path=/",
            },
            """
            <html>
                <head><title>PsyberShield Demo</title></head>
                <body>
                    <h1>PsyberShield Demo Site</h1>
                    <a href=\"/.env\">.env</a>
                    <a href=\"/backup.zip\">backup</a>
                </body>
            </html>
            """.strip(),
        )

    if path == "/.env":
        return (
            200,
            {
                "Content-Type": "text/plain; charset=utf-8",
            },
            "SECRET=demo\n",
        )

    if path == "/backup.zip":
        return (
            200,
            {
                "Content-Type": "application/zip",
            },
            "not a real zip, just a demo file\n",
        )

    return (
        404,
        {
            "Content-Type": "text/plain; charset=utf-8",
        },
        "not found\n",
    )


class DemoSiteHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    def do_GET(self) -> None:
        # Serve a tiny target that gives the scanner something useful to find locally.
        status, headers, body = demo_page(self.path)
        self.send_response(status)
        for name, value in headers.items():
            if name.lower() == "server":
                continue
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format: str, *args) -> None:
        return


def serve_demo_site(port: int = 8000) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), DemoSiteHandler)
    try:
        print(f"PsyberShield demo site running on http://127.0.0.1:{port}")
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
