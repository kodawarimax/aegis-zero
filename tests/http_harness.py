"""Exercise the real HTTP parser/handler without opening network sockets."""
import http.client
import io
from types import SimpleNamespace

from aegis.server import create_request_handler


class MemorySocket:
    def __init__(self, incoming):
        self.incoming = io.BytesIO(incoming)
        self.outgoing = io.BytesIO()

    def makefile(self, *args, **kwargs):
        return self.incoming

    def sendall(self, data):
        self.outgoing.write(data)

    def settimeout(self, timeout):
        pass


def raw_request(state, request):
    sock = MemorySocket(request)
    create_request_handler(state)(sock, ("127.0.0.1", 54999), SimpleNamespace())
    response = http.client.HTTPResponse(MemorySocket(sock.outgoing.getvalue()))
    response.begin()
    return response.status, response.read().decode("utf-8")


def request(state, method, path, headers=None, body=None):
    body = body.encode("utf-8") if isinstance(body, str) else body or b""
    h = {"Host": f"127.0.0.1:{state.port}"}
    h.update(headers or {})
    if method == "POST" and "Content-Length" not in h:
        h["Content-Length"] = str(len(body))
    head = f"{method} {path} HTTP/1.0\r\n" + "".join(f"{k}: {v}\r\n" for k, v in h.items())
    return raw_request(state, head.encode("latin-1") + b"\r\n" + body)
