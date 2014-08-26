import re
from socket import socket

from sslscan import modules
from sslscan.module.handler.tcp import TCP


class HTTP(TCP):
    """
    Handle HTTP-connections.

    Handle HTTP-connections and extract additional information.
    """

    name = "http"

    _regex_status = re.compile("^(?P<version>HTTP\/1\.[01])\s+(?P<code>[0-9]+)\s+(?P<message>.*?)$")

    def __init__(self, **kwargs):
        self.port = 443
        TCP.__init__(self, **kwargs)

    def request(self, conn):
        conn.send(b"GET / HTTP/1.1\r\n")
        conn.send(b"User-Agent: SSLScan\r\n")
        conn.send("Host: {0}\r\n".format(self.hostname).encode("utf-8"))
        conn.send(b"\r\n")
        data = b""
        while True:
            data = data + conn.recv(32)
            if data.find(b"\r\n\r\n") >= 0:
                break

        lines = data.splitlines()
        if len(lines) == 0:
            return None

        m = self._regex_status.match(lines.pop(0).decode('iso-8859-1'))
        if not m:
            return None

        result = {
            "code": int(m.group("code")),
            "headers": [],
            "message": m.group("message"),
            "version": m.group("version")
        }

        for line in lines:
            if line == "":
                break
            line = line.decode('iso-8859-1')
            name, sep, value = line.partition(":")
            result["headers"].append((name, value))

        if self._server_info is None:
            self._server_info = result


modules.register(HTTP)
