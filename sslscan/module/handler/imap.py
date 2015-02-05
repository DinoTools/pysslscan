import re
from socket import socket

from sslscan import modules
from sslscan.exception import StartTLSError
from sslscan.module.handler.tcp import TCP


class IMAP(TCP):
    """
    Handle IMAP-connections.
    """

    name = "imap"

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
        self.port = 143
        TCP.__init__(self, **kwargs)

    def _connect(self, conn):
        server_info = {}
        buf = conn.recv(4096)
        try:
            buf = buf.decode("ASCII")
            buf = buf.strip()
        except:
            pass

        # ToDo: improve parsing
        server_info["banner"] = buf
        if self._server_info is None:
            self._server_info = server_info

    def connect(self):
        # ToDo: raise exception
        conn = TCP.connect(self)
        if not self.config.get_value("starttls"):
            return conn

        self._connect(conn)

        conn.send(b". STARTTLS\r\n")
        buf = conn.recv(4096)
        buf = buf.strip()
        if not buf.startswith(b". OK"):
            raise StartTLSError()

        return conn

    def get_server_info(self, conn=None):
        if self._server_info is None and conn is not None:
            self._connect(conn)
        return self._server_info


modules.register(IMAP)
