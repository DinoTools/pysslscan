from socket import socket

from sslscan import modules
from sslscan.exception import StartTLSError
from sslscan.module.handler.tcp import TCP


class LDAP(TCP):
    """
    Handle LDAP-connections.
    """

    name = "ldap"

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
        self.port = 389
        TCP.__init__(self, **kwargs)

    def connect(self):
        # ToDo: raise exception
        conn = TCP.connect(self)
        if not self.config.get_value("starttls"):
            return conn

        conn.send(b"0\x1d\x02\x01\x01w\x18\x80\x161.3.6.1.4.1.1466.20037")

        buf = conn.recv(4096)

        # ToDo: Improve parsing
        # b"0\x84\x00\x00\x00(\x02\x01\x01x\x84\x00\x00\x00\x1f\n\x01\x00\x04\x00\x04\x00\x8a\x161.3.6.1.4.1.1466.20037"
        if not buf.endswith(b"1.3.6.1.4.1.1466.20037"):
            raise StartTLSError()

        return conn

modules.register(LDAP)