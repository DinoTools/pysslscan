import re
from smtplib import SMTP as PySMTP
from socket import socket

from sslscan import modules
from sslscan.exception import StartTLSError
from sslscan.module.handler.tcp import TCP


regex_banner = re.compile(b"^(?P<code>\d+) (?P<hostname>\S+) \S+ (?P<banner>.*)$")


class SMTP(TCP):
    """
    Handle SMTP-connections.
    """

    name = "smtp"

    config_options = TCP.config_options + [
        (
            "starttls", {
                "default": False,
                "help": "",
                "type": "bool"
            }
        )
    ]

    def __init__(self, **kwargs):
        self.port = 25
        TCP.__init__(self, **kwargs)

    def _connect(self, conn):
        server_info = {}
        buf = conn.recv(4096)
        if not buf.startswith(b"220"):
            return None

        if self._server_info is None:
            m = regex_banner.match(buf)
            if m:
                server_info["banner"] = m.group("banner")

        conn.send(b"EHLO example.org\r\n")
        buf = conn.recv(4096)
        if not buf.startswith(b"250"):
            return None

        if self._server_info is None:
            self._server_info = server_info

    def connect(self):
        # ToDo: raise exception
        conn = TCP.connect(self)
        if not self.config.get_value("starttls"):
            return conn

        self._connect(conn)

        conn.send(b"STARTTLS\r\n")
        buf = conn.recv(4096)
        if not buf.startswith(b"220"):
            raise StartTLSError()

        return conn

    def get_server_info(self, conn=None):
        if self._server_info is None and conn is not None:
            self._connect(conn)
        return self._server_info



modules.register(SMTP)
