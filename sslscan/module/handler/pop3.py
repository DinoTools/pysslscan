import re

from sslscan import modules
from sslscan.exception import StartTLSError
from sslscan.module.handler.tcp import TCP


regex_banner = re.compile(b"\\+OK (?P<hostname>\S+) .*")


class POP3(TCP):
    """
    Handle POP3-connections.
    """

    name = "pop3"

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
        self.port = 110
        TCP.__init__(self, **kwargs)

    def _connect(self, conn):
        server_info = {}
        buf = conn.recv(4096)

        m = regex_banner.match(buf)
        if m:
            hostname = m.group("hostname")
            try:
                hostname = hostname.decode("ASCII")
            except:
                hostname = str(hostname)
            server_info["hostname"] = hostname

        if self._server_info is None:
            self._server_info = server_info

    def connect(self):
        # ToDo: raise exception
        conn = TCP.connect(self)
        if not self.config.get_value("starttls"):
            return conn

        self._connect(conn)

        conn.send(b"STLS\r\n")
        buf = conn.recv(4096)
        buf = buf.strip()
        # +OK Begin TLS negotiation now'
        # ToDo:
        # print(buf)
        if not buf.startswith(b"+OK Begin"):
            raise StartTLSError()

        return conn

    def get_server_info(self, conn=None):
        if self._server_info is None and conn is not None:
            self._connect(conn)
        return self._server_info


modules.register(POP3)
